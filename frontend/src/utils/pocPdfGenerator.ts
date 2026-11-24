/**
 * OWASP Sentinel - Publication-Grade Vector PDF Dossier Generator
 * High-fidelity, multi-page vector PDF generation using jsPDF
 *
 * Implements Standard Enterprise VAPT PoC Report Structure:
 * - Subject Line
 * - Subline
 * - Reporting To
 * - Confidentiality
 * - Priority
 * - VAPT Scope
 * - Proof: SS (Screenshot / Wire Evidence Capture), URL (Target Endpoint)
 * - Problem Faced
 * - Example (Exploitation Scenario)
 * - Solution (Production Hardening Guidance & Patch)
 * - Work (Implementation & Verification Checklist)
 */

import { jsPDF } from 'jspdf';
import type { Finding, AuthorizedAsset } from '../types/api';
import { buildStructuredPoCFinding, getPoCPriority } from './pocReportStructure';

export type AudienceViewMode = 'DUAL' | 'EXECUTIVE' | 'TECHNICAL';

export interface GeneratePoCPdfOptions {
  audienceView?: AudienceViewMode;
  targetHeaderLabel: string;
  docDate: string;
  assetsCount: number;
  postureScore: number;
  activeFindings: Finding[];
  remediatedCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  assets: AuthorizedAsset[];
  targetAsset: AuthorizedAsset | null;
  fileSlug: string;
}

export function generatePoCPdf(options: GeneratePoCPdfOptions): { success: boolean; pageCount: number } {
  const {
    audienceView = 'DUAL',
    targetHeaderLabel,
    docDate,
    assetsCount,
    postureScore,
    activeFindings,
    remediatedCount,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    assets,
    targetAsset,
    fileSlug,
  } = options;

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 12;
  const contentWidth = pageWidth - margin * 2; // 186mm
  let y = margin;

  const checkPage = (needed: number) => {
    if (y + needed > pageHeight - margin - 10) {
      doc.addPage();
      y = margin;
    }
  };

  const getSeverityColors = (
    sev: string
  ): { bg: [number, number, number]; text: [number, number, number]; border: [number, number, number] } => {
    switch (sev) {
      case 'CRITICAL':
        return { bg: [254, 226, 226], text: [153, 27, 27], border: [248, 113, 113] };
      case 'HIGH':
        return { bg: [255, 237, 213], text: [154, 52, 18], border: [251, 146, 60] };
      case 'MEDIUM':
        return { bg: [254, 243, 199], text: [146, 64, 14], border: [251, 191, 36] };
      case 'LOW':
        return { bg: [224, 242, 254], text: [3, 105, 161], border: [56, 189, 248] };
      default:
        return { bg: [241, 245, 249], text: [51, 65, 85], border: [203, 213, 225] };
    }
  };

  const maxSeverity = criticalCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : mediumCount > 0 ? 'MEDIUM' : 'LOW';
  const overallPriority = getPoCPriority(maxSeverity);

  // =========================================================================
  // 1. TOP DOCUMENT AUTHORITY BANNER
  // =========================================================================
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(margin, y, contentWidth, 22, 'F');

  // Title adapted to Audience Mode
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11.5);
  doc.setTextColor(255, 255, 255);

  const docTitle =
    audienceView === 'EXECUTIVE'
      ? 'OWASP SENTINEL - EXECUTIVE RISK ADVISORY (NON-IT)'
      : audienceView === 'TECHNICAL'
      ? 'OWASP SENTINEL - TECHNICAL AUDITOR DOSSIER (IT)'
      : 'OWASP SENTINEL - PROOF OF CONCEPT (PoC) VAPT ADVISORY';
  doc.text(docTitle, margin + 4, y + 8);

  // Subtitle adapted to Audience Mode
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(56, 189, 248); // cyan-400

  const docSubtitle =
    audienceView === 'EXECUTIVE'
      ? 'EXECUTIVE LEADERSHIP DOSSIER | VAPT AUDIT & BUSINESS RISK IMPACT'
      : audienceView === 'TECHNICAL'
      ? 'TECHNICAL AUDITOR & ENGINEERING DOSSIER | EMPIRICAL WIRE PROOFS & HARDENING'
      : 'AUTONOMOUS APPLICATION SECURITY INSPECTION | VAPT AUDIT & PROOF OF CONCEPT';
  doc.text(docSubtitle, margin + 4, y + 14.5);

  // Classification Badge
  const badgeColor: [number, number, number] =
    audienceView === 'EXECUTIVE' ? [217, 119, 6] : audienceView === 'TECHNICAL' ? [2, 132, 199] : [225, 29, 72];
  doc.setFillColor(badgeColor[0], badgeColor[1], badgeColor[2]);
  doc.rect(pageWidth - margin - 60, y + 4.5, 56, 6, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.2);
  doc.setTextColor(255, 255, 255);

  const badgeText =
    audienceView === 'EXECUTIVE'
      ? 'RESTRICTED // EXECUTIVE BRIEFING'
      : audienceView === 'TECHNICAL'
      ? 'RESTRICTED // TECHNICAL AUDIT'
      : 'RESTRICTED // FOR AUTHORIZED EYES ONLY';
  doc.text(badgeText, pageWidth - margin - 32, y + 8.8, { align: 'center' });

  y += 26;

  // =========================================================================
  // 2. DOCUMENT-LEVEL VAPT METADATA CARD (Subject Line, Subline, Reporting To, etc.)
  // =========================================================================
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.3);
  doc.rect(margin, y, contentWidth, 34, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(15, 23, 42);

  // Line 1: Subject Line
  doc.text('Subject Line:', margin + 4, y + 5.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(2, 132, 199);
  const cleanSubject = `Web Application Penetration Testing (VAPT) PoC Advisory - ${targetHeaderLabel}`;
  doc.text(cleanSubject.length > 78 ? cleanSubject.slice(0, 75) + '...' : cleanSubject, margin + 24, y + 5.5);

  // Line 2: Subline
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Subline:', margin + 4, y + 10.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('Empirical Security Flaw Assessment, Wire Telemetry & Production Hardening Directives', margin + 24, y + 10.5);

  // Line 3: Reporting To & Confidentiality
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Reporting To:', margin + 4, y + 15.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);
  doc.text('Chief Information Security Officer (CISO) & Application Security Committee', margin + 24, y + 15.5);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Confidentiality:', margin + 115, y + 15.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(190, 18, 60);
  doc.text('RESTRICTED ACCESS', margin + 137, y + 15.5);

  // Line 4: Priority & VAPT
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Priority:', margin + 4, y + 20.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(180, 83, 9);
  doc.text(`${overallPriority.label}`, margin + 24, y + 20.5);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('VAPT Scope:', margin + 115, y + 20.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('DAST & ASVS v4.0.3 Socket Audit', margin + 134, y + 20.5);

  // Line 5: Audit Scope & Posture Score
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Audit Date:', margin + 4, y + 26);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(`${docDate} (${assetsCount} In-Scope Targets)`, margin + 24, y + 26);

  const postureStatus =
    postureScore >= 80 ? 'Hardened Defenses' : postureScore >= 50 ? 'Elevated Risk' : 'Critical Action Required';
  const scoreR = postureScore >= 80 ? 22 : postureScore >= 50 ? 194 : 225;
  const scoreG = postureScore >= 80 ? 163 : postureScore >= 50 ? 65 : 29;
  const scoreB = postureScore >= 80 ? 74 : postureScore >= 50 ? 12 : 72;
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(scoreR, scoreG, scoreB);
  doc.text(`Posture Score: ${postureScore}/100 (${postureStatus}) - ${activeFindings.length} Confirmed Active`, margin + 85, y + 26);

  y += 38;

  // =========================================================================
  // 3. EXECUTIVE BRIEFING / TECHNICAL PARAMETERS CARD
  // =========================================================================
  if (audienceView === 'TECHNICAL') {
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(2, 132, 199);
    doc.setLineWidth(0.4);
    doc.rect(margin, y, contentWidth, 23, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(2, 132, 199);
    doc.text('TECHNICAL SCOPE & EMPIRICAL VERIFICATION PARAMETERS (IT AUDITOR)', margin + 4, y + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 41, 59);

    doc.setFont('helvetica', 'bold');
    doc.text('- Audit Methodology:', margin + 4, y + 10.5);
    doc.setFont('helvetica', 'normal');
    doc.text('RFC specifications, OWASP ASVS v4.0.3 standards, deterministic shell commands & socket analysis.', margin + 35, y + 10.5);

    doc.setFont('helvetica', 'bold');
    doc.text('- Verification Boundary:', margin + 4, y + 15);
    doc.setFont('helvetica', 'normal');
    doc.text('Strictly non-destructive live HTTP probes, verifiable wire responses, and repeatable cURL reproductions.', margin + 37, y + 15);

    doc.setFont('helvetica', 'bold');
    doc.text('- Engineering Action:', margin + 4, y + 19.5);
    doc.setFont('helvetica', 'normal');
    doc.text('Apply production configuration patches and directives listed in the technical telemetry below.', margin + 34, y + 19.5);

    y += 27;
  } else {
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(34, 197, 94);
    doc.setLineWidth(0.4);
    doc.rect(margin, y, contentWidth, 23, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(22, 101, 52);
    doc.text('EXECUTIVE BRIEFING: WHAT NON-TECHNICAL LEADERSHIP NEEDS TO KNOW', margin + 4, y + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);

    doc.setFont('helvetica', 'bold');
    doc.text('- Threat Exposure:', margin + 4, y + 10.5);
    doc.setFont('helvetica', 'normal');
    doc.text('Missing transport hardening, exposed server signatures, or insufficient browser controls.', margin + 30, y + 10.5);

    doc.setFont('helvetica', 'bold');
    doc.text('- Business Consequence:', margin + 4, y + 15);
    doc.setFont('helvetica', 'normal');
    doc.text('User session interception on public Wi-Fi, site impersonation risk, and compliance audit penalties.', margin + 38, y + 15);

    doc.setFont('helvetica', 'bold');
    doc.text('- Recommended Action:', margin + 4, y + 19.5);
    doc.setFont('helvetica', 'normal');
    doc.text('Direct web engineering to apply the verified configuration directives prioritized below.', margin + 37, y + 19.5);

    y += 27;
  }

  // =========================================================================
  // 4. SEVERITY BREAKDOWN MATRIX
  // =========================================================================
  const sevCols = [
    { label: 'CRITICAL (P1)', count: criticalCount, color: [225, 29, 72] as [number, number, number] },
    { label: 'HIGH (P2)', count: highCount, color: [234, 88, 12] as [number, number, number] },
    { label: 'MEDIUM (P3)', count: mediumCount, color: [217, 119, 6] as [number, number, number] },
    { label: 'LOW (P4)', count: lowCount, color: [2, 132, 199] as [number, number, number] },
    { label: 'INFO (P5)', count: infoCount, color: [100, 116, 139] as [number, number, number] },
    { label: 'REMEDIATED', count: remediatedCount, color: [22, 163, 74] as [number, number, number] },
  ];

  const colWidth = (contentWidth - 5 * 2) / 6;
  sevCols.forEach((col, i) => {
    const xPos = margin + i * (colWidth + 2);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.rect(xPos, y, colWidth, 13, 'FD');

    doc.setFillColor(col.color[0], col.color[1], col.color[2]);
    doc.rect(xPos, y, colWidth, 1.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.2);
    doc.setTextColor(col.color[0], col.color[1], col.color[2]);
    doc.text(col.label, xPos + colWidth / 2, y + 5.5, { align: 'center' });

    doc.setFontSize(10);
    doc.text(String(col.count), xPos + colWidth / 2, y + 11, { align: 'center' });
  });

  y += 18;

  // SECTION DIVIDER TITLE
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  const sectionTitle =
    audienceView === 'EXECUTIVE'
      ? 'VAPT Proof of Concept Dossier (Executive Presentation)'
      : audienceView === 'TECHNICAL'
      ? 'VAPT Proof of Concept Dossier (Technical Auditor Telemetry)'
      : 'VAPT Proof of Concept Dossier (Dual Executive & Technical View)';
  doc.text(sectionTitle, margin, y);
  y += 5;

  // =========================================================================
  // 5. DETAILED FINDINGS DOSSIER (Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT, Proof: SS/URL, Problem Faced, Example, Solution, Work)
  // =========================================================================
  activeFindings.forEach((f, idx) => {
    const item = buildStructuredPoCFinding(f, assets, targetAsset);
    const sevColors = getSeverityColors(f.severity);

    // Ensure finding header has room
    checkPage(40);

    // Finding Header Box
    doc.setFillColor(sevColors.bg[0], sevColors.bg[1], sevColors.bg[2]);
    doc.setDrawColor(sevColors.border[0], sevColors.border[1], sevColors.border[2]);
    doc.setLineWidth(0.3);
    doc.rect(margin, y, contentWidth, 9, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(sevColors.text[0], sevColors.text[1], sevColors.text[2]);
    doc.text(`[${item.priority.code}]`, margin + 3, y + 6);

    doc.setTextColor(15, 23, 42);
    const titleText = `#${idx + 1}  ${f.title}`;
    const truncatedTitle = titleText.length > 76 ? titleText.slice(0, 73) + '...' : titleText;
    doc.text(truncatedTitle, margin + 20, y + 6);

    y += 11;

    // --- A. VAPT REPORT HEADER BLOCK (Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT) ---
    checkPage(24);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.rect(margin, y, contentWidth, 20, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(15, 23, 42);

    doc.text('Subject Line:', margin + 3, y + 4.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(2, 132, 199);
    doc.text(item.subjectLine.length > 80 ? item.subjectLine.slice(0, 77) + '...' : item.subjectLine, margin + 22, y + 4.5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Subline:', margin + 3, y + 8.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(item.subline.length > 80 ? item.subline.slice(0, 77) + '...' : item.subline, margin + 22, y + 8.5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Reporting To:', margin + 3, y + 12.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(item.reportingTo, margin + 22, y + 12.5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Confidentiality:', margin + 115, y + 12.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(190, 18, 60);
    doc.text('RESTRICTED ACCESS', margin + 137, y + 12.5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Priority:', margin + 3, y + 16.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(180, 83, 9);
    doc.text(item.priority.label, margin + 22, y + 16.5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('VAPT Scope:', margin + 115, y + 16.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(`Rule: ${item.ruleId}`, margin + 134, y + 16.5);

    y += 23;

    // --- B. PROOF SECTION (Proof: SS, URL) ---
    checkPage(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('PROOF DOSSIER (URL & EMPIRICAL SS CAPTURE):', margin + 2, y);
    y += 4.5;

    // 1. Proof: URL
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(2, 132, 199);
    doc.text('- Proof: URL (Tested Target Endpoint):', margin + 4, y);
    doc.setFont('courier', 'normal');
    doc.setTextColor(15, 23, 42);
    doc.text(item.proof.url, margin + 58, y);
    y += 4.5;

    // 2. Proof: SS (Screenshot / Wire Telemetry Capture)
    const ssBoxLines = [
      `[SNAPSHOT PROOF: SS - WIRE EVIDENCE CAPTURE]`,
      `Probe Dispatched: ${item.proof.probe}`,
      `Target Response Status: ${item.proof.serverStatus} | Latency: ${item.proof.latencyMs}ms | Host: ${item.proof.resolvedIp}:${item.proof.port}`,
      `Observed Defect: ${item.proof.observedDefect}`,
      `Expected Baseline Standard: ${item.proof.expectedStandard}`,
    ];

    const ssBoxHeight = ssBoxLines.length * 4.2 + 6;
    checkPage(ssBoxHeight + 5);

    doc.setFillColor(15, 23, 42); // slate-900 (Terminal / Screenshot frame)
    doc.rect(margin + 2, y, contentWidth - 4, ssBoxHeight, 'F');

    let curSsY = y + 4.5;
    doc.setFont('courier', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(56, 189, 248); // cyan-400
    doc.text(ssBoxLines[0], margin + 5, curSsY);
    curSsY += 4.2;

    doc.setFont('courier', 'normal');
    doc.setTextColor(241, 245, 249);
    for (let sIdx = 1; sIdx < ssBoxLines.length; sIdx++) {
      const wrapped = doc.splitTextToSize(ssBoxLines[sIdx], contentWidth - 10);
      wrapped.forEach((line: string) => {
        doc.text(line, margin + 5, curSsY);
        curSsY += 3.8;
      });
    }

    y += ssBoxHeight + 3;



    if (item.proof.reproductionCli && audienceView !== 'EXECUTIVE') {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(2, 132, 199);
      doc.text('- Deterministic Shell Reproduction Command (cURL CLI):', margin + 4, y);
      y += 4;

      doc.setFont('courier', 'bold');
      doc.setFontSize(7);
      const cliLines = doc.splitTextToSize(item.proof.reproductionCli, contentWidth - 8);
      const cliHeight = Math.max(8, cliLines.length * 4 + 4);
      checkPage(cliHeight + 4);

      doc.setFillColor(15, 23, 42);
      doc.rect(margin + 2, y, contentWidth - 4, cliHeight, 'F');
      doc.setTextColor(56, 189, 248);
      let curCliY = y + 4;
      cliLines.forEach((l: string) => {
        doc.text(l, margin + 5, curCliY);
        curCliY += 3.8;
      });
      y += cliHeight + 3;
    }

    // --- C. PROBLEM FACED ---
    checkPage(24);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(180, 83, 9); // amber-700
    doc.text('PROBLEM FACED (Defect Analysis & Perimeter Failure):', margin + 2, y);
    y += 4.5;

    const probLines = doc.splitTextToSize(item.problemFaced, contentWidth - 8);
    const probBoxHeight = probLines.length * 3.8 + 6;
    checkPage(probBoxHeight + 4);

    doc.setFillColor(254, 252, 232); // light amber
    doc.setDrawColor(245, 158, 11);
    doc.setLineWidth(0.3);
    doc.rect(margin + 2, y, contentWidth - 4, probBoxHeight, 'FD');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 41, 59);
    let curProbY = y + 4.5;
    probLines.forEach((line: string) => {
      doc.text(line, margin + 5, curProbY);
      curProbY += 3.8;
    });
    y += probBoxHeight + 4;

    // --- D. EXAMPLE (Real-World Attack Scenario) ---
    checkPage(24);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('EXAMPLE (Real-World Adversarial Exploitation Scenario):', margin + 2, y);
    y += 4.5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const exampleRaw = String(item.example);
    const exampleSteps = exampleRaw.split('\n').filter((s) => s.trim().length > 0);
    exampleSteps.forEach((st: string) => {
      const stepLines = doc.splitTextToSize(st.trim(), contentWidth - 8);
      stepLines.forEach((sl: string) => {
        checkPage(4.5);
        doc.text(sl, margin + 5, y);
        y += 3.8;
      });
    });
    y += 3;

    // --- E. SOLUTION (Production Hardening & Architecture Fix) ---
    checkPage(26);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(22, 101, 52); // green-700
    doc.text('SOLUTION (Production Hardening Directives & Architecture Fix):', margin + 2, y);
    y += 4.5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const solLines = doc.splitTextToSize(item.solution, contentWidth - 8);
    solLines.forEach((sl: string) => {
      checkPage(4.5);
      doc.text(sl, margin + 5, y);
      y += 3.8;
    });

    if (item.solutionCode && audienceView !== 'EXECUTIVE') {
      const patchLines = doc.splitTextToSize(item.solutionCode, contentWidth - 10);
      const patchHeight = Math.max(8, patchLines.length * 4 + 4);
      checkPage(patchHeight + 4);

      doc.setFillColor(240, 253, 244); // light green
      doc.setDrawColor(34, 197, 94);
      doc.setLineWidth(0.3);
      doc.rect(margin + 2, y, contentWidth - 4, patchHeight, 'FD');

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(22, 101, 52);
      let curPatchY = y + 4;
      patchLines.forEach((pl: string) => {
        doc.text(pl, margin + 5, curPatchY);
        curPatchY += 3.8;
      });
      y += patchHeight + 4;
    } else {
      y += 3;
    }

    // --- F. WORK (Implementation & Verification Checklist) ---
    checkPage(28);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('WORK (Engineering & Operational Implementation Tasks):', margin + 2, y);
    y += 4.5;

    item.work.tasks.forEach((task) => {
      checkPage(10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(2, 132, 199);
      doc.text(`[${task.role}] Task ${task.id}: ${task.title}`, margin + 5, y);
      y += 3.8;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(71, 85, 105);
      const tDesc = doc.splitTextToSize(task.description, contentWidth - 12);
      tDesc.forEach((td: string) => {
        doc.text(td, margin + 8, y);
        y += 3.5;
      });
      y += 1.5;
    });

    // Divider line between findings
    y += 2;
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.line(margin, y, pageWidth - margin, y);
    y += 7;
  });

  // =========================================================================
  // 6. GLOBAL FOOTERS ON ALL PAGES
  // =========================================================================
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.25);
    doc.line(margin, pageHeight - 9, pageWidth - margin, pageHeight - 9);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);

    const footerMode =
      audienceView === 'EXECUTIVE'
        ? 'Executive Risk Advisory'
        : audienceView === 'TECHNICAL'
        ? 'Technical Auditor Dossier'
        : 'PoC Security Advisory';
    doc.text(`OWASP Sentinel | ${footerMode}`, margin, pageHeight - 5);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 5, { align: 'center' });
    doc.text('CONFIDENTIAL // AUTHORIZED AUDIT', pageWidth - margin, pageHeight - 5, { align: 'right' });
  }

  // TRIGGER DIRECT FILE DOWNLOAD IN BROWSER
  const viewSlug =
    audienceView === 'EXECUTIVE' ? 'Executive-NonIT' : audienceView === 'TECHNICAL' ? 'Technical-IT' : 'Dual-View';
  const filename = `PoC-${viewSlug}-${fileSlug}-${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);

  return { success: true, pageCount: totalPages };
}

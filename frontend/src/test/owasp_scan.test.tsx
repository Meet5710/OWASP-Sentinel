import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { Sidebar } from '../components/Sidebar';
import { OwaspScanTab, OWASP_TOP10_2025 } from '../components/OwaspScanTab';

describe('OWASP Scan Side Panel & Component', () => {
  it('OWASP SCAN accordion is closed by default in the sidebar', () => {
    render(
      <Sidebar
        activeTab="overview"
        setActiveTab={vi.fn()}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={vi.fn()}
      />
    );

    // Main item is visible
    expect(screen.getByText('OWASP SCAN')).toBeInTheDocument();
    // Subcategories should NOT be rendered by default
    expect(screen.queryByText('Broken Access Control')).not.toBeInTheDocument();
    expect(screen.getByTitle('Expand subcategories')).toBeInTheDocument();
  });

  it('renders OWASP SCAN and all 10 subcategories in the sidebar when expanded', () => {
    const setActiveTab = vi.fn();
    const onSelectOwaspCategory = vi.fn();

    render(
      <Sidebar
        activeTab="owasp_scan"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={vi.fn()}
        selectedOwaspCategory="A01"
        onSelectOwaspCategory={onSelectOwaspCategory}
        defaultOwaspExpanded={true}
      />
    );

    // Verify main OWASP SCAN menu item
    expect(screen.getAllByText('OWASP SCAN').length).toBeGreaterThan(0);

    // Verify all 10 subcategories A01 to A10 are rendered in side panel
    expect(screen.getAllByText('Broken Access Control').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Security Misconfiguration').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Software Supply Chain Failures').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Cryptographic Failures').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Injection').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Insecure Design').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Authentication Failures').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Software or Data Integrity Failures').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Security Logging and Alerting Failures').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Mishandling of Exceptional Conditions').length).toBeGreaterThan(0);
  });

  it('triggers selection when a subcategory is clicked in sidebar', () => {
    const setActiveTab = vi.fn();
    const onSelectOwaspCategory = vi.fn();

    render(
      <Sidebar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'healthy', version: '0.1.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={vi.fn()}
        selectedOwaspCategory="A01"
        onSelectOwaspCategory={onSelectOwaspCategory}
      />
    );

    // Expand accordion first
    const expandBtn = screen.getByTitle('Expand subcategories');
    fireEvent.click(expandBtn);

    const injectionBtn = screen.getByTitle('A05: Injection');
    fireEvent.click(injectionBtn);

    expect(setActiveTab).toHaveBeenCalledWith('owasp_scan');
    expect(onSelectOwaspCategory).toHaveBeenCalledWith('A05');
  });

  it('renders OwaspScanTab and generates the command', () => {
    render(
      <OwaspScanTab
        selectedCategory="A01"
        assets={[{ id: '1', canonical_url: 'https://test.local', hostname: 'test.local', port: 443, scheme: 'https', is_subdomain: false, approval_status: 'APPROVED', first_discovered_at: '', last_assessed_at: '' }]}
      />
    );

    expect(screen.getAllByText('run_access_control_checks()').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/python -m scanner\.main scan --target/)).toBeInTheDocument();
    expect(screen.getByText('▶ Execute Scan')).toBeInTheDocument();
  });

  it('triggers execute scan API call and displays findings', async () => {
    const mockFindings = {
      target: 'https://target.local',
      findings: [
        {
          owasp_id: 'A02',
          title: 'Missing Security Header: CSP',
          severity: 'medium',
          evidence: 'Content-Security-Policy header is missing',
          source: 'scanner',
        },
      ],
      summary: {
        total: 1,
        by_owasp: { A01: 0, A02: 1 },
      },
    };

    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => mockFindings,
    } as Response);

    render(
      <OwaspScanTab
        selectedCategory="A02"
        assets={[]}
      />
    );

    const executeBtn = screen.getByText('▶ Execute Scan');
    await act(async () => {
      fireEvent.click(executeBtn);
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/api/scan',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: expect.stringContaining('"selected_checks"'),
      })
    );

    // Verify findings rendered
    expect(await screen.findByText('Scan Results for https://target.local')).toBeInTheDocument();
    expect(screen.getByText('Missing Security Header: CSP')).toBeInTheDocument();

    fetchSpy.mockRestore();
  });

  it('handles scan API error and alerts user', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    const fetchSpy = vi.spyOn(global, 'fetch').mockRejectedValue(
      new Error('Connection refused')
    );

    render(
      <OwaspScanTab
        selectedCategory="A01"
        assets={[]}
      />
    );

    const executeBtn = screen.getByText('▶ Execute Scan');
    await act(async () => {
      fireEvent.click(executeBtn);
    });

    await vi.waitFor(() => {
      expect(alertSpy).toHaveBeenCalledWith(expect.stringContaining('Connection refused'));
    });

    expect(screen.getByText(/Scan Error:/)).toBeInTheDocument();

    alertSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it('filters categories by search query including CWE examples', () => {
    render(<OwaspScanTab selectedCategory="A01" assets={[]} />);

    const searchInput = screen.getByPlaceholderText(
      /Search categories by ID, name, CWE/
    );

    // Search by CWE-89 (SQL Injection)
    fireEvent.change(searchInput, { target: { value: 'CWE-89' } });

    expect(screen.getByRole('heading', { level: 4, name: 'Injection' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 4, name: 'Broken Access Control' })).not.toBeInTheDocument();

    // Clear search
    fireEvent.change(searchInput, { target: { value: '' } });
    expect(screen.getByRole('heading', { level: 4, name: 'Broken Access Control' })).toBeInTheDocument();
  });

  it('filters categories by automation status pill and selects filtered items', () => {
    render(<OwaspScanTab selectedCategory="A01" assets={[]} />);

    // Click Manual Review filter pill
    const manualBtn = screen.getByText(/Manual Review \(3\)/);
    fireEvent.click(manualBtn);

    expect(screen.getByRole('heading', { level: 4, name: 'Insecure Design' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 4, name: 'Security Logging and Alerting Failures' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 4, name: 'Mishandling of Exceptional Conditions' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 4, name: 'Broken Access Control' })).not.toBeInTheDocument();

    // Click Select Filtered
    const selectFilteredBtn = screen.getByText('Select Filtered');
    fireEvent.click(selectFilteredBtn);

    // Verify command builder contains manual checks
    expect(screen.getByText(/--checks.*A06/)).toBeInTheDocument();
  });
});

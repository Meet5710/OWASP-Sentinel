import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Sidebar } from '../components/Sidebar';
import { PathFinderTab } from '../components/PathFinderTab';
import type { AuthorizedAsset, PathFinderScan, DiscoveredPath } from '../types/api';
import { api } from '../services/api';

const mockAssets: AuthorizedAsset[] = [
  {
    id: 'asset-test-01',
    scope_grant_id: 'scope-01',
    canonical_url: 'https://test-target.org/',
    host: 'test-target.org',
    hostname: 'test-target.org',
    port: 443,
    scheme: 'https',
    is_subdomain: false,
    approval_status: 'APPROVED',
  },
  {
    id: 'asset-unapproved-02',
    scope_grant_id: 'scope-01',
    canonical_url: 'https://unapproved.org/',
    host: 'unapproved.org',
    hostname: 'unapproved.org',
    port: 443,
    scheme: 'https',
    is_subdomain: false,
    approval_status: 'REJECTED',
  },
];

const mockSamplePaths: DiscoveredPath[] = [
  {
    id: 'p-1',
    scan_id: 'scan-01',
    path: '/api/v1/auth/login',
    full_url: 'https://test-target.org/api/v1/auth/login',
    status_code: 200,
    content_length: 1420,
    content_type: 'application/json',
    redirect_url: null,
    response_time_ms: 45,
    discovered_at: '2026-11-20T10:00:00Z',
  },
  {
    id: 'p-2',
    scan_id: 'scan-01',
    path: '/admin',
    full_url: 'https://test-target.org/admin',
    status_code: 301,
    content_length: 320,
    content_type: 'text/html',
    redirect_url: 'https://test-target.org/admin/login',
    response_time_ms: 120,
    discovered_at: '2026-11-20T10:00:05Z',
  },
  {
    id: 'p-3',
    scan_id: 'scan-01',
    path: '/internal/metrics',
    full_url: 'https://test-target.org/internal/metrics',
    status_code: 403,
    content_length: 512,
    content_type: 'text/plain',
    redirect_url: null,
    response_time_ms: 60,
    discovered_at: '2026-11-20T10:00:10Z',
  },
];

const mockPastScans: PathFinderScan[] = [
  {
    id: 'scan-past-01',
    target_id: 'asset-test-01',
    user_id: 'usr-1',
    mode: 'QUICK',
    config_json: { mode: 'QUICK' },
    status: 'COMPLETED',
    progress_percent: 100,
    started_at: '2026-11-20T08:00:00Z',
    completed_at: '2026-11-20T08:02:15Z',
    created_at: '2026-11-20T08:00:00Z',
    updated_at: '2026-11-20T08:02:15Z',
    total_discovered_paths: 3,
  },
];

describe('Path Finder Sidebar and Tab Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'getPathFinderScans').mockResolvedValue(mockPastScans);
    vi.spyOn(api, 'getDiscoveredPaths').mockResolvedValue(mockSamplePaths);
  });

  it('renders Path Finder item in Sidebar and triggers navigation', () => {
    const setActiveTab = vi.fn();
    render(
      <Sidebar
        activeTab="overview"
        setActiveTab={setActiveTab}
        systemHealth={{ status: 'HEALTHY', version: '1.0.0' }}
        isSimulatedMode={false}
        setIsSimulatedMode={vi.fn()}
      />
    );

    const pathFinderBtn = screen.getByText('Path Finder');
    expect(pathFinderBtn).toBeInTheDocument();

    fireEvent.click(pathFinderBtn);
    expect(setActiveTab).toHaveBeenCalledWith('pathfinder');
  });

  it('renders Path Finder Tab with target selector, controls, and metrics', async () => {
    render(<PathFinderTab assets={mockAssets} />);

    expect(screen.getByText('Authorized Endpoint Discovery')).toBeInTheDocument();
    expect(screen.getByText('Start Endpoint Discovery')).toBeInTheDocument();
    expect(screen.getByText('Total Discovered')).toBeInTheDocument();
    expect(screen.getByText('200 Accessible')).toBeInTheDocument();
    expect(screen.getByText('3xx Redirects')).toBeInTheDocument();
    expect(screen.getByText('403 Auth Gates')).toBeInTheDocument();
    expect(screen.getByText('Elapsed Time')).toBeInTheDocument();
    expect(screen.getByText('Throughput')).toBeInTheDocument();
  });

  it('populates target selector exclusively with approved assets', async () => {
    render(<PathFinderTab assets={mockAssets} />);

    // Click target dropdown
    const targetTrigger = screen.getByText('test-target.org');
    expect(targetTrigger).toBeInTheDocument();
    fireEvent.click(targetTrigger);

    // Verify search input is rendered
    const searchInput = screen.getByPlaceholderText('Search authorized inventory...');
    expect(searchInput).toBeInTheDocument();

    // Verify unapproved asset is strictly excluded
    expect(screen.queryByText('unapproved.org')).not.toBeInTheDocument();
  });

  it('toggles scan mode between Quick Scan and Deep Probing', () => {
    render(<PathFinderTab assets={mockAssets} />);

    const quickBtn = screen.getByText('Quick Scan');
    const deepBtn = screen.getByText('Deep Probing');

    expect(quickBtn).toBeInTheDocument();
    expect(deepBtn).toBeInTheDocument();

    fireEvent.click(deepBtn);
    expect(deepBtn.closest('button')).toHaveClass('text-cyan-400');

    fireEvent.click(quickBtn);
    expect(quickBtn.closest('button')).toHaveClass('text-emerald-400');
  });

  it('expands advanced settings for wordlist, concurrency, and custom headers', () => {
    render(<PathFinderTab assets={mockAssets} />);

    const advancedToggle = screen.getByText('Show Advanced Options');
    fireEvent.click(advancedToggle);

    expect(screen.getByText('Routing Wordlist')).toBeInTheDocument();
    expect(screen.getByText('Concurrency Threads')).toBeInTheDocument();
    expect(screen.getByText('Rate Limit (RPS)')).toBeInTheDocument();
    expect(screen.getByText('Custom Assessment Headers')).toBeInTheDocument();
    expect(screen.getByDisplayValue('X-Sentinel-Authorized-Assessment')).toBeInTheDocument();
  });

  it('renders discovered endpoints in table with status badges and redirect links', async () => {
    render(<PathFinderTab assets={mockAssets} />);

    await waitFor(() => {
      expect(screen.getByText('/api/v1/auth/login')).toBeInTheDocument();
      expect(screen.getByText('/admin')).toBeInTheDocument();
      expect(screen.getByText('/internal/metrics')).toBeInTheDocument();
      expect(screen.getByText('200 OK')).toBeInTheDocument();
      expect(screen.getByText('301 REDIRECT')).toBeInTheDocument();
      expect(screen.getByText('403 FORBIDDEN')).toBeInTheDocument();
      expect(screen.getByText('https://test-target.org/admin/login')).toBeInTheDocument();
    });
  });

  it('filters discovered endpoints by status chips and search query', async () => {
    render(<PathFinderTab assets={mockAssets} />);

    await waitFor(() => {
      expect(screen.getByText('/api/v1/auth/login')).toBeInTheDocument();
    });

    // Filter by 403 Forbidden chip
    const forbiddenChip = screen.getByText(/403 Protected/);
    fireEvent.click(forbiddenChip);

    expect(screen.getByText('/internal/metrics')).toBeInTheDocument();
    expect(screen.queryByText('/api/v1/auth/login')).not.toBeInTheDocument();

    // Reset to all
    const allChip = screen.getByText(/All \(/);
    fireEvent.click(allChip);
    expect(screen.getByText('/api/v1/auth/login')).toBeInTheDocument();

    // Filter by search query
    const searchInput = screen.getByPlaceholderText('Search paths or redirects...');
    fireEvent.change(searchInput, { target: { value: 'admin' } });

    expect(screen.getByText('/admin')).toBeInTheDocument();
    expect(screen.queryByText('/api/v1/auth/login')).not.toBeInTheDocument();
  });

  it('switches to Scan History view and allows reopening past scans', async () => {
    render(<PathFinderTab assets={mockAssets} />);

    const historyTabBtn = screen.getByText('Scan History');
    fireEvent.click(historyTabBtn);

    await waitFor(() => {
      expect(screen.getByText('Historical Path Finder Runs')).toBeInTheDocument();
      expect(screen.getByText('3 routes')).toBeInTheDocument();
      expect(screen.getByText('View Results')).toBeInTheDocument();
    });

    // Click Reopen / View Results
    const viewResultsBtn = screen.getByText('View Results');
    fireEvent.click(viewResultsBtn);

    // Should switch back to dashboard view with results loaded
    expect(screen.getByText('Authorized Scoped Target')).toBeInTheDocument();
  });
});

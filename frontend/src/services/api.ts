/**
 * OWASP Sentinel - Central API Client Service
 */

import type {
  AuthorizedAsset,
  ScopeGrant,
  ScanJob,
  Finding,
  OWASPEdition,
  IngestionRun,
  LineageThemeItem,
  CoverageMatrixItem,
  DetectionRule,
  ScheduledScan,
  FindingHistoryRecord,
  PatchVerification,
  AuditEvent,
  SubdomainDiscoveryRequest,
  SubdomainDiscoveryResponse,
  ScanTerminalResponse,
  NgrokStatus,
  DorkGenerateResponse,
  DorkPreset,
  DorkSaveRequest,
  DorkSaveResponse,
  HarvestUrlsRequest,
  HarvestUrlsResponse,
  FeedToScannerRequest,
  FeedToScannerResponse,
  ProxyValidateRequest,
  ProxyValidateResponse,
  ProxySaveRequest,
  ProxySaveResponse,
  ProxyPoolConfig,
  ProxyPreset,
  DorkFileInfo,
  Layer3ScanRequest,
  Layer3ScanResponse,
  Layer3Summary,
  DatabaseChannelInfo,
  Layer4ExploitRequest,
  Layer4ExploitResponse,
  Layer5EnumRequest,
  Layer5EnumResponse,
  Layer6DumpRequest,
  Layer6DumpResponse,
  Layer6ExportRequest,
  Layer6ExportResponse,
  PathFinderScan,
  PathFinderScanCreate,
  PathFinderScanUpdateStatus,
  DiscoveredPath,
} from '../types/api';

const API_BASE = '/api/v1';

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'ngrok-skip-browser-warning': 'true',
    ...(options.headers || {}),
  };

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (typeof errJson.detail === 'string') {
        errorDetail = errJson.detail;
      } else if (errJson.detail && typeof errJson.detail.message === 'string') {
        errorDetail = errJson.detail.message;
      } else if (typeof errJson.message === 'string') {
        errorDetail = errJson.message;
      } else if (typeof errJson.error === 'string') {
        errorDetail = errJson.error;
      } else {
        errorDetail = JSON.stringify(errJson);
      }
    } catch {
      // fallback to status text
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  // System Health
  async getHealth(): Promise<{ status: string; version: string; service: string }> {
    return request('/health');
  },

  // Target Input Validation
  async validateTarget(target: string, is_authorized: boolean): Promise<any> {
    return request('/targets/validate', {
      method: 'POST',
      body: JSON.stringify({ target, is_authorized }),
    });
  },

  // Subdomain Discovery & Asset Reconnaissance
  async findSubdomains(payload: SubdomainDiscoveryRequest): Promise<SubdomainDiscoveryResponse> {
    return request('/targets/find-subdomains', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async findSubdomainsStream(
    payload: SubdomainDiscoveryRequest,
    onEvent: (event: any) => void,
    signal?: AbortSignal
  ): Promise<void> {
    const url = `${API_BASE}/targets/find-subdomains/stream`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true',
      },
      body: JSON.stringify(payload),
      signal,
    });

    if (!response.ok) {
      let errMsg = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errJson = await response.json();
        errMsg = errJson.message || errJson.detail || errMsg;
      } catch {
        // fallback
      }
      throw new Error(errMsg);
    }

    const reader = response.body?.getReader();
    if (!reader) return;
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const ev = JSON.parse(line);
          onEvent(ev);
        } catch {
          // ignore malformed
        }
      }
    }
    if (buffer.trim()) {
      try {
        onEvent(JSON.parse(buffer));
      } catch {
        // ignore
      }
    }
  },

  // Scopes
  async getScopes(): Promise<ScopeGrant[]> {
    return request('/scopes');
  },

  async createScope(data: Partial<ScopeGrant> & { organization_name: string }): Promise<ScopeGrant> {
    return request('/scopes', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Authorized Assets
  async getAssets(): Promise<AuthorizedAsset[]> {
    return request('/assets');
  },

  async registerAsset(data: {
    target: string;
    scope_code: string;
    is_authorized: boolean;
    skip_dns_resolution?: boolean;
    approval_notes?: string;
  }): Promise<AuthorizedAsset> {
    return request('/assets', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async approveAsset(assetId: string, status: 'APPROVED' | 'REJECTED', notes?: string): Promise<AuthorizedAsset> {
    return request(`/assets/${assetId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ status, notes }),
    });
  },

  async deleteAsset(assetId: string): Promise<{ status: string; message: string }> {
    return request(`/assets/${assetId}`, {
      method: 'DELETE',
    });
  },

  async deleteAssetsByDomain(domain: string): Promise<{ status: string; deleted_count: number; message: string }> {
    return request(`/assets/bulk/by-domain?domain=${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
  },

  // Scans
  async getScans(assetId?: string): Promise<ScanJob[]> {
    const q = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : '';
    return request(`/scans${q}`);
  },

  async triggerScan(assetId: string, ruleIds?: string[]): Promise<ScanJob> {
    return request('/scans/execute', {
      method: 'POST',
      body: JSON.stringify({ asset_id: assetId, rule_ids: ruleIds }),
    });
  },

  async getScanDetails(scanId: string): Promise<ScanJob> {
    return request(`/scans/${scanId}`);
  },

  async getScanTerminalLogs(scanId: string): Promise<ScanTerminalResponse> {
    return request(`/scans/${scanId}/terminal`);
  },

  async getScanObservations(scanId: string): Promise<any[]> {
    return request(`/scans/${scanId}/observations`);
  },

  // Rules & Coverage
  async getRules(): Promise<DetectionRule[]> {
    const raw = await request<any[]>('/rules');
    return (raw || []).map((r: any) => ({
      rule_id: r.rule_id,
      name: r.name,
      description: r.description,
      severity: r.severity || 'INFO',
      confidence: r.confidence || 'CERTAIN',
      category_mappings: r.owasp_category_mappings || r.category_mappings || {},
      what_it_tests: r.what_it_tests || r.description || '',
      why_it_matters: r.why_it_matters || '',
      evidence_collected: Array.isArray(r.evidence_collected)
        ? r.evidence_collected
        : typeof r.evidence_description === 'string'
        ? [r.evidence_description]
        : [],
      required_permissions: Array.isArray(r.required_permissions)
        ? r.required_permissions
        : typeof r.required_permissions === 'string'
        ? [r.required_permissions]
        : [],
      known_limitations: Array.isArray(r.known_limitations)
        ? r.known_limitations
        : typeof r.known_limitations === 'string'
        ? [r.known_limitations]
        : [],
      potential_false_positives: Array.isArray(r.potential_false_positives)
        ? r.potential_false_positives
        : typeof r.potential_false_positives === 'string'
        ? [r.potential_false_positives]
        : [],
      remediation_guidance: r.remediation_guidance || '',
    }));
  },

  async getCoverageMatrix(edition: string = '2025'): Promise<{
    edition: string;
    total_categories: number;
    automated_count: number;
    partial_count: number;
    manual_review_count: number;
    no_detection_count: number;
    matrix: CoverageMatrixItem[];
  }> {
    const res = await request<any>(`/rules/coverage/matrix?edition=${encodeURIComponent(edition)}`);
    const rawMatrix = res.coverage_matrix || res.matrix || [];
    return {
      edition: res.edition || edition,
      total_categories: res.total_categories || rawMatrix.length,
      automated_count: res.categories_with_automated_rules || res.automated_count || 0,
      partial_count: res.partial_count || 0,
      manual_review_count: res.categories_requiring_manual_review || res.manual_review_count || 0,
      no_detection_count: res.uncovered_categories || res.no_detection_count || 0,
      matrix: rawMatrix.map((item: any) => ({
        category_identifier: item.category_code || item.category_identifier || '',
        title: item.category_title || item.title || '',
        status: (item.coverage_status === 'AUTOMATED_CHECKS'
          ? 'FULL_AUTOMATED'
          : item.coverage_status === 'MANUAL_REVIEW_REQUIRED'
          ? 'MANUAL_REVIEW_REQUIRED'
          : item.coverage_status === 'NO_IMPLEMENTED_DETECTION'
          ? 'NO_DETECTION'
          : item.status || 'NO_DETECTION'),
        automated_rules: item.rule_ids || item.automated_rules || [],
        capabilities: item.capabilities?.length ? item.capabilities : item.rule_names || [],
        limitations: item.limitations?.length ? item.limitations : ['Non-destructive passive and active HTTP inspection boundary.'],
        manual_review_guidance: item.manual_review_guidance || (item.coverage_status === 'MANUAL_REVIEW_REQUIRED' ? 'Requires manual security assessment and architecture review.' : undefined),
      })),
    };
  },

  // Findings
  async getFindings(params: {
    target_id?: string;
    scan_id?: string;
    severity?: string;
    validation_status?: string;
    edition?: string;
    category?: string;
    active_only?: boolean;
  } = {}): Promise<Finding[]> {
    const q = new URLSearchParams();
    if (params.target_id) q.set('target_id', params.target_id);
    if (params.scan_id) q.set('scan_id', params.scan_id);
    if (params.severity) q.set('severity', params.severity);
    if (params.validation_status) q.set('validation_status', params.validation_status);
    if (params.edition) q.set('edition', params.edition);
    if (params.category) q.set('category', params.category);
    if (params.active_only) q.set('active_only', 'true');
    const qs = q.toString() ? `?${q.toString()}` : '';
    return request(`/findings${qs}`);
  },

  async getFinding(findingId: string): Promise<Finding> {
    return request(`/findings/${findingId}`);
  },

  async updateFindingStatus(findingId: string, new_status: string, note: string, actor: string = 'Security Engineer'): Promise<Finding> {
    return request(`/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ validation_status: new_status, new_status, note, actor }),
    });
  },

  // Taxonomy & Ingestion
  async getLineageTimeline(): Promise<LineageThemeItem[]> {
    return request<LineageThemeItem[]>('/taxonomy/lineage');
  },

  async getTaxonomyEditions(): Promise<OWASPEdition[]> {
    const raw = await request<any[]>('/taxonomy/editions');
    return (raw || []).map((e: any) => ({
      id: e.id,
      identifier: e.edition_identifier || e.identifier || '',
      title: e.title || '',
      publication_year: e.publication_year || 0,
      source_url: e.source_url || '',
      is_active: e.is_latest ?? true,
      categories: (e.categories || []).map((c: any) => ({
        id: c.id,
        edition_identifier: e.edition_identifier || e.identifier || '',
        category_identifier: c.category_code || c.category_identifier || '',
        title: c.category_title || c.title || '',
        order_index: c.display_order ?? c.order_index ?? 0,
        description: c.category_description || c.description || '',
        source_reference_url: c.source_url || c.source_reference_url || '',
        retrieval_timestamp: c.retrieval_timestamp || e.retrieval_timestamp || new Date().toISOString(),
        content_hash: c.content_hash || '',
        cwe_examples: Array.isArray(c.cwe_examples) ? c.cwe_examples : [],
      })),
    }));
  },

  async getEdition(identifier: string): Promise<OWASPEdition> {
    const e = await request<any>(`/taxonomy/editions/${identifier}`);
    return {
      id: e.id,
      identifier: e.edition_identifier || e.identifier || '',
      title: e.title || '',
      publication_year: e.publication_year || 0,
      source_url: e.source_url || '',
      is_active: e.is_latest ?? true,
      categories: (e.categories || []).map((c: any) => ({
        id: c.id,
        edition_identifier: e.edition_identifier || e.identifier || '',
        category_identifier: c.category_code || c.category_identifier || '',
        title: c.category_title || c.title || '',
        order_index: c.display_order ?? c.order_index ?? 0,
        description: c.category_description || c.description || '',
        source_reference_url: c.source_url || c.source_reference_url || '',
        retrieval_timestamp: c.retrieval_timestamp || e.retrieval_timestamp || new Date().toISOString(),
        content_hash: c.content_hash || '',
        cwe_examples: Array.isArray(c.cwe_examples) ? c.cwe_examples : [],
      })),
    };
  },

  async triggerIngestion(): Promise<IngestionRun> {
    const r = await request<any>('/taxonomy/ingest', { method: 'POST' });
    return {
      id: r.id,
      status: r.status,
      editions_processed: r.editions_processed ?? 8,
      categories_processed: r.categories_processed ?? ((r.editions_processed || 8) * 10),
      changes_detected: r.changes_detected ?? (r.status === 'CHANGES_DETECTED' || (r.categories_created > 0 || r.categories_updated > 0)),
      admin_review_required: r.admin_review_required ?? r.requires_admin_review ?? false,
      error_message: r.error_message,
      started_at: r.started_at,
      completed_at: r.completed_at,
    };
  },

  async getIngestionHistory(): Promise<IngestionRun[]> {
    const raw = await request<any[]>('/taxonomy/ingest/history');
    return (raw || []).map((r: any) => ({
      id: r.id,
      status: r.status,
      editions_processed: r.editions_processed ?? 8,
      categories_processed: r.categories_processed ?? ((r.editions_processed || 8) * 10),
      changes_detected: r.changes_detected ?? (r.status === 'CHANGES_DETECTED' || (r.categories_created > 0 || r.categories_updated > 0)),
      admin_review_required: r.admin_review_required ?? r.requires_admin_review ?? false,
      error_message: r.error_message,
      started_at: r.started_at,
      completed_at: r.completed_at,
    }));
  },

  // Schedules
  async getSchedules(): Promise<ScheduledScan[]> {
    return request('/schedules');
  },

  async createSchedule(data: {
    target_id: string;
    frequency: string;
    cron_expression?: string;
    rule_ids?: string[];
  }): Promise<ScheduledScan> {
    return request('/schedules', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateSchedule(scheduleId: string, is_active: boolean): Promise<ScheduledScan> {
    return request(`/schedules/${scheduleId}`, {
      method: 'PATCH',
      body: JSON.stringify({ is_active }),
    });
  },

  async runDueSchedules(): Promise<{ executed_jobs: ScanJob[]; count: number }> {
    return request('/schedules/run-due', { method: 'POST' });
  },

  // History & Timeline
  async getPostureTimeline(targetId: string): Promise<{
    target_id: string;
    canonical_url: string;
    history_records: FindingHistoryRecord[];
    recent_verifications: PatchVerification[];
  }> {
    return request(`/history/timeline/${targetId}`);
  },

  // Audit
  async getAuditEvents(limit: number = 100): Promise<AuditEvent[]> {
    return request(`/audit?limit=${limit}`);
  },

  // Terminal Execution
  async executeTerminalCommand(data: {
    command: string;
    target_host?: string;
    target_port?: string;
    target_url?: string;
    target_scheme?: string;
    target_id?: string;
    custom_script_name?: string;
    custom_script_content?: string;
    current_dir?: string;
  }): Promise<{
    command: string;
    stdout: string;
    stderr: string;
    returncode: number;
    duration_ms: number;
    execution_type: string;
    is_upgraded?: boolean;
    fs_entries?: Array<{ name: string; type: 'directory' | 'file'; size: number; modified: number }>;
    current_dir?: string;
  }> {
    return request('/terminal/execute', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Streaming Terminal Execution with Live Output
  async executeTerminalStream(
    data: {
      command: string;
      target_host?: string;
      target_port?: string;
      target_url?: string;
      target_scheme?: string;
      target_id?: string;
      custom_script_name?: string;
      custom_script_content?: string;
      current_dir?: string;
    },
    onLine: (line: string) => void,
    onDone: (result: { returncode: number; bugs_count?: number; current_dir?: string; fs_entries?: any[] }) => void,
    onError: (err: any) => void
  ): Promise<() => void> {
    const controller = new AbortController();
    const url = `${API_BASE}/terminal/execute-stream`;

    (async () => {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'ngrok-skip-browser-warning': 'true',
          },
          body: JSON.stringify(data),
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status} ${response.statusText}`);
        }

        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error('ReadableStream not supported on this browser');
        }

        const decoder = new TextDecoder();
        let buffer = '';
        let isDoneCalled = false;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split('\n');
          buffer = parts.pop() || '';

          for (const rawPart of parts) {
            const line = rawPart.trim();
            if (!line) continue;
            try {
              const parsed = JSON.parse(line);
              if (parsed.event === 'line') {
                onLine(parsed.data);
              } else if (parsed.event === 'error') {
                onLine(`[-] ${parsed.data}`);
              } else if (parsed.event === 'complete') {
                isDoneCalled = true;
                onDone(parsed);
              }
            } catch {
              onLine(line);
            }
          }
        }

        if (buffer.trim()) {
          try {
            const parsed = JSON.parse(buffer.trim());
            if (parsed.event === 'line') onLine(parsed.data);
            else if (parsed.event === 'complete') {
              isDoneCalled = true;
              onDone(parsed);
            }
          } catch {
            onLine(buffer.trim());
          }
        }

        if (!isDoneCalled) {
          isDoneCalled = true;
          onDone({ returncode: 0 });
        }
      } catch (err: any) {
        if (err.name !== 'AbortError') {
          onError(err);
        }
      }
    })();

    return () => {
      controller.abort();
    };
  },

  async getTerminalFilesystem(path?: string): Promise<{
    current_dir: string;
    entries: Array<{ name: string; type: 'directory' | 'file'; size: number; modified: number }>;
  }> {
    const q = path ? `?path=${encodeURIComponent(path)}` : '';
    return request(`/terminal/fs${q}`);
  },

  async getTerminalAptStatus(): Promise<{
    is_upgraded: boolean;
    last_updated: number | null;
    origin_date: string | null;
    kernel_version: string;
  }> {
    return request('/terminal/apt-status');
  },

  async getPracticeScriptSource(scriptName: string): Promise<{ script_name: string; content: string }> {
    return request(`/terminal/script-source?script_name=${encodeURIComponent(scriptName)}`);
  },

  // Ngrok Public Tunnel Management
  async getNgrokStatus(): Promise<NgrokStatus> {
    return request('/tunnel/status');
  },

  async startNgrokTunnel(authtoken?: string): Promise<NgrokStatus> {
    return request('/tunnel/start', {
      method: 'POST',
      body: JSON.stringify({ authtoken: authtoken || '' }),
    });
  },

  async stopNgrokTunnel(): Promise<NgrokStatus> {
    return request('/tunnel/stop', {
      method: 'POST',
    });
  },

  async setNgrokAuthtoken(authtoken: string): Promise<{ success: boolean; message: string }> {
    return request('/tunnel/authtoken', {
      method: 'POST',
      body: JSON.stringify({ authtoken }),
    });
  },

  // SQL Module: Target Discovery with Dork Engine
  async getDorkPresets(): Promise<DorkPreset[]> {
    return request('/sql/dorks/presets');
  },

  async generateDorks(data: {
    keywords: string[];
    formats: string[];
    page_types: string[];
    target_domain?: string;
    keyword_operator?: string;
    format_operator?: string;
    max_dorks?: number;
  }): Promise<DorkGenerateResponse> {
    return request('/sql/dorks/generate', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async saveDorksToFile(data: DorkSaveRequest): Promise<DorkSaveResponse> {
    return request('/sql/dorks/save', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async harvestCandidateUrls(data: HarvestUrlsRequest): Promise<HarvestUrlsResponse> {
    return request('/sql/urls/harvest', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async feedUrlsToScanner(data: FeedToScannerRequest): Promise<FeedToScannerResponse> {
    return request('/sql/scanner/feed', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Layer 2: Proxy Layer (Anonymity/Evasion)
  async getProxyPresets(): Promise<ProxyPreset[]> {
    return request('/sql/proxies/presets');
  },

  async validateProxies(data: ProxyValidateRequest): Promise<ProxyValidateResponse> {
    return request('/sql/proxies/validate', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async saveProxiesToFile(data: ProxySaveRequest): Promise<ProxySaveResponse> {
    return request('/sql/proxies/save', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getSavedProxies(filename = 'proxies.txt'): Promise<{ filename: string; exists: boolean; raw_text: string; proxies: string[]; count: number }> {
    return request(`/sql/proxies/saved?filename=${encodeURIComponent(filename)}`);
  },

  async getActiveProxyPool(): Promise<ProxyPoolConfig> {
    return request('/sql/proxies/active');
  },

  async setActiveProxyPool(data: ProxyPoolConfig): Promise<ProxyPoolConfig> {
    return request('/sql/proxies/active', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Layer 3: Scanning and Classification
  async getDorkFiles(): Promise<DorkFileInfo[]> {
    return request('/sql/dork-files');
  },

  async runLayer3Scan(data: Layer3ScanRequest): Promise<Layer3ScanResponse> {
    return request('/sql/layer3/scan', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getLayer3Results(targetDomain?: string): Promise<Layer3Summary> {
    const q = targetDomain ? `?target_domain=${encodeURIComponent(targetDomain)}` : '';
    return request(`/sql/layer3/results${q}`);
  },

  async clearLayer3Trash(): Promise<{ status: string; purged_count: number; remaining_count: number; message: string }> {
    return request('/sql/layer3/clear-trash', {
      method: 'POST',
    });
  },

  // Layer 4: Exploitation Engine
  async executeLayer4Exploit(data: Layer4ExploitRequest): Promise<Layer4ExploitResponse> {
    return request('/sql/layer4/exploit', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getLayer4ChannelStatus(): Promise<DatabaseChannelInfo> {
    return request('/sql/layer4/channel');
  },

  // Layer 5: Hierarchical Database Enumeration & Data Dump Engine
  async enumerateLayer5(data: Layer5EnumRequest): Promise<Layer5EnumResponse> {
    return request('/sql/layer5/enumerate', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Layer 6: Data Extraction and Export Engine
  async dumpLayer6(data: Layer6DumpRequest): Promise<Layer6DumpResponse> {
    return request('/sql/layer6/dump', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async exportLayer6(data: Layer6ExportRequest): Promise<Layer6ExportResponse> {
    return request('/sql/layer6/export', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Path Finder (Authorized Endpoint Discovery) Endpoints
  async getPathFinderScans(params?: { target_id?: string; status?: string; limit?: number; offset?: number }): Promise<PathFinderScan[]> {
    const q = new URLSearchParams();
    if (params?.target_id) q.set('target_id', params.target_id);
    if (params?.status) q.set('status', params.status);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.offset) q.set('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return request(`/path-finder/scans${qs}`);
  },

  async createPathFinderScan(data: PathFinderScanCreate): Promise<PathFinderScan> {
    return request('/path-finder/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getPathFinderScan(scanId: string): Promise<PathFinderScan> {
    return request(`/path-finder/scans/${scanId}`);
  },

  async updatePathFinderScanStatus(scanId: string, data: PathFinderScanUpdateStatus): Promise<PathFinderScan> {
    return request(`/path-finder/scans/${scanId}/status`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  async getDiscoveredPaths(scanId: string, params?: { status_code?: number; search?: string; limit?: number; offset?: number }): Promise<DiscoveredPath[]> {
    const q = new URLSearchParams();
    if (params?.status_code !== undefined) q.set('status_code', String(params.status_code));
    if (params?.search) q.set('search', params.search);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.offset) q.set('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return request(`/path-finder/scans/${scanId}/paths${qs}`);
  },

  async recordDiscoveredPaths(scanId: string, paths: Partial<DiscoveredPath>[]): Promise<DiscoveredPath[]> {
    return request(`/path-finder/scans/${scanId}/paths`, {
      method: 'POST',
      body: JSON.stringify(paths),
    });
  },

  async deletePathFinderScan(scanId: string): Promise<void> {
    return request(`/path-finder/scans/${scanId}`, {
      method: 'DELETE',
    });
  },

  async controlPathFinderScan(scanId: string, action: 'pause' | 'resume' | 'cancel'): Promise<PathFinderScan> {
    return request(`/path-finder/scans/${scanId}/control`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
  },

  async exportPathFinderScan(scanId: string, format: 'json' | 'csv' = 'json'): Promise<Blob | any> {
    const res = await fetch(`${API_BASE}/path-finder/scans/${scanId}/export?format=${format}`);
    if (!res.ok) {
      throw new Error(`Export failed: ${res.statusText}`);
    }
    if (format === 'csv') {
      return res.blob();
    }
    return res.json();
  },

  createPathFinderEventSource(scanId: string): EventSource {
    return new EventSource(`${API_BASE}/path-finder/scans/${scanId}/stream`);
  },

  // XSSSpect Assessment Engine
  async launchXSSpectScan(data: {
    url: string;
    target_id?: string;
    parameters?: string[];
    payload_file?: string;
    delay?: number;
    use_playwright?: boolean;
    detection_mode?: string;
  }): Promise<{
    url: string;
    target_id?: string;
    parameters_tested: string[];
    findings: Array<{
      parameter: string;
      payload: string;
      executed: boolean;
      reflected: boolean;
      dialog_message?: string | null;
      error?: string | null;
    }>;
    vulnerable: boolean;
    error?: string | null;
  }> {
    return request('/xssspect/scan', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};


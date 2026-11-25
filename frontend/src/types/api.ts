/**
 * OWASP Sentinel - TypeScript Type Definitions
 * Directly matching FastAPI Pydantic & SQLAlchemy Models
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ValidationStatus = 'POTENTIAL' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'MITIGATED';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type ApprovalStatus = 'APPROVED' | 'PENDING' | 'REJECTED' | 'BASELINE';

export type PatchVerificationStatus = 'STILL_VULNERABLE' | 'REMEDIATED' | 'REGRESSED';

export interface ScopeGrant {
  id: string;
  organization_id: string;
  scope_code: string;
  title: string;
  description?: string;
  authorized_by: string;
  permitted_ports: number[];
  permitted_schemes: string[];
  allow_subdomains: boolean;
  max_requests_per_minute: number;
  valid_from: string;
  valid_until: string;
  is_active: boolean;
  created_at: string;
}

export interface AuthorizedAsset {
  id: string;
  scope_grant_id: string;
  canonical_url: string;
  hostname?: string;
  host?: string;
  port: number;
  scheme: string;
  ip_address?: string;
  resolved_ips?: string[];
  is_subdomain?: boolean;
  approval_status: ApprovalStatus;
  approval_notes?: string;
  created_at?: string;
  first_discovered_at?: string;
  last_assessed_at?: string;
}

export interface DiscoveredSubdomain {
  subdomain: string;
  canonical_url: string;
  ip_addresses: string[];
  is_live: boolean;
  scheme: string;
  port: number;
  status_code?: number | null;
  response_time_ms?: number | null;
  server_banner?: string | null;
  page_title?: string | null;
  live_scraped?: boolean;
  sources: string[];
  is_already_in_inventory: boolean;
  existing_asset_id?: string | null;
}

export interface SubdomainDiscoveryResponse {
  target_domain: string;
  total_discovered: number;
  live_count: number;
  dns_active_count?: number;
  live_scraped_count?: number;
  sources_summary?: Record<string, number>;
  subdomains: DiscoveredSubdomain[];
  discovered_at: string;
}

export interface SubdomainDiscoveryRequest {
  domain: string;
  include_dns_probe?: boolean;
  include_cert_transparency?: boolean;
  verify_live?: boolean;
  continuous_scan?: boolean;
  deep_scan?: boolean;
  include_permutations?: boolean;
  enable_live_scraping?: boolean;
  scrape_depth?: number;
}

export interface TechnicalObservation {
  id: string;
  scan_id: string;
  rule_id: string;
  technical_issue_type: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: string;
  evidence: Record<string, any>;
  observed_at: string;
}

export interface FindingCategoryMapping {
  id: string;
  finding_id?: string;
  edition_identifier: string;
  category_identifier: string;
  owasp_edition?: string;
  owasp_category_code?: string;
  owasp_category_title?: string;
  justification: string;
}

export interface StatusHistoryEntry {
  from_status: string;
  to_status: string;
  timestamp: string;
  actor: string;
  note: string;
}

export interface Finding {
  id: string;
  target_id: string;
  scan_id?: string;
  initial_scan_id?: string;
  last_scan_id?: string;
  rule_id: string;
  technical_issue_type: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: string;
  validation_status: ValidationStatus;
  remediation_guidance: string;
  remediation_recommendations?: string;
  references: string[];
  evidence: Record<string, any>;
  status_history: StatusHistoryEntry[];
  first_seen_at: string;
  last_seen_at: string;
  category_mappings: FindingCategoryMapping[];
}

export interface OWASPCategory {
  id: string;
  edition_identifier: string;
  category_identifier: string;
  title: string;
  order_index: number;
  description: string;
  source_reference_url: string;
  retrieval_timestamp: string;
  content_hash: string;
  cwe_examples?: string[];
}

export interface OWASPEdition {
  id: string;
  identifier: string;
  title: string;
  publication_year: number;
  source_url: string;
  is_active: boolean;
  categories: OWASPCategory[];
}

export interface IngestionRun {
  id: string;
  status: string;
  editions_processed: number;
  categories_processed: number;
  changes_detected: boolean;
  admin_review_required: boolean;
  error_message?: string;
  started_at: string;
  completed_at: string;
}

export interface LineageThemeItem {
  id: string;
  theme: string;
  current_status: string;
  current_2025_category: string;
  description: string;
  years_present_summary: string;
  timeline: Record<string, string>;
  notable_changes: string;
}

export interface CoverageMatrixItem {
  category_identifier: string;
  title: string;
  status: 'FULL_AUTOMATED' | 'PARTIAL_AUTOMATED' | 'MANUAL_REVIEW_REQUIRED' | 'NO_DETECTION';
  automated_rules: string[];
  capabilities: string[];
  limitations: string[];
  manual_review_guidance?: string;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  confidence: string;
  category_mappings: Record<string, string>;
  what_it_tests: string;
  why_it_matters: string;
  evidence_collected: string[];
  required_permissions: string[];
  known_limitations: string[];
  potential_false_positives: string[];
  remediation_guidance: string;
}

export interface TerminalLogEntry {
  timestamp: string;
  time_display: string;
  level: string; // 'INIT' | 'SCOPE' | 'SCAN' | 'RECON' | 'CRYPTO' | 'EXEC' | 'AUDIT' | 'FAIL' | 'PROOF' | 'PASS' | 'TAXONOMY' | 'COMPLETE' | 'ERROR'
  rule_id: string;
  message: string;
  detail?: any;
}

export interface PracticalProof {
  proof_type: string;
  target_endpoint: string;
  header_or_field: string;
  assertion_tested: string;
  observed_finding: string;
  expected_standard: string;
  security_impact: string;
  remediation_code: string;
}

export interface NetworkReconDetails {
  resolved_ip: string;
  port: number;
  scheme: string;
  latency_ms: number;
  tls_version?: string;
  tls_cipher?: string;
  http_version?: string;
}

export interface ScanTerminalResponse {
  scan_id: string;
  target_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  terminal_logs: TerminalLogEntry[];
  recon_details?: NetworkReconDetails;
  deep_scan_metrics?: {
    total_checks: number;
    passed_checks: number;
    failed_checks: number;
    compliance_rate: number;
    execution_time_seconds: number;
    latency_ms: number;
    resolved_ip: string;
    tls_cipher?: string;
    tls_version?: string;
  };
}

export interface ScanJob {
  id: string;
  asset_id?: string;
  target_id?: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  created_at?: string;
  error_message?: string;
  total_checks?: number;
  passed_checks?: number;
  failed_checks?: number;
  observations_count: number;
  scan_metadata?: Record<string, any>;
}

export interface ScheduledScan {
  id: string;
  target_id: string;
  scope_grant_id: string;
  frequency: string;
  cron_expression?: string;
  is_active: boolean;
  next_run_at: string;
  last_run_at?: string;
  last_scan_id?: string;
  rule_ids: string[];
  created_at: string;
}

export interface PatchVerification {
  id: string;
  finding_id: string;
  scan_id: string;
  target_id: string;
  verification_status: PatchVerificationStatus;
  notes: string;
  evidence: Record<string, any>;
  verified_at: string;
}

export interface FindingHistoryRecord {
  id: string;
  target_id: string;
  scan_id: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  new_findings_count: number;
  resolved_findings_count: number;
  recurrent_findings_count: number;
  recorded_at: string;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  actor: string;
  target_id?: string;
  scope_id?: string;
  description: string;
  metadata_payload?: Record<string, any>;
  metadata_json?: Record<string, any>;
  created_at?: string;
  timestamp?: string;
}


export interface NgrokTunnelInfo {
  name: string;
  public_url: string;
  proto: string;
  addr?: string;
}

export interface NgrokStatus {
  is_running: boolean;
  public_url: string | null;
  proto: string | null;
  tunnels: NgrokTunnelInfo[];
  authtoken_configured: boolean;
  error?: string | null;
}

export interface GeneratedDork {
  dork_query: string;
  keyword: string;
  format: string;
  page_type: string;
  target_domain?: string | null;
  search_urls: {
    google?: string;
    bing?: string;
    duckduckgo?: string;
    yahoo?: string;
    yandex?: string;
    startpage?: string;
    github?: string;
    shodan?: string;
    [key: string]: string | undefined;
  };
  category: string;
  risk_profile: string;
  sqlmap_example: string;
}

export interface DorkGenerateResponse {
  total_generated: number;
  target_domain?: string | null;
  dorks: GeneratedDork[];
  keywords_used: string[];
  formats_used: string[];
  page_types_used: string[];
}

export interface DorkPreset {
  id: string;
  name: string;
  description: string;
  keywords: string[];
  formats: string[];
  page_types: string[];
  icon: string;
}

export interface DorkSaveRequest {
  lines: string[];
  filename?: string;
  category?: string;
}

export interface DorkSaveResponse {
  filename: string;
  file_path: string;
  total_lines: number;
  message: string;
}

export interface CandidateUrl {
  url: string;
  host: string;
  parameters: string[];
  source_engine: string;
  dork_query?: string | null;
  status: 'PENDING' | 'LIVE' | 'OFFLINE' | string;
  status_code?: number | null;
  discovered_at?: string | null;
}

export interface HarvestUrlsRequest {
  queries: string[];
  engines?: string[];
  max_urls_per_engine?: number;
  target_domain?: string | null;
  verify_live?: boolean;
}

export interface HarvestUrlsResponse {
  total_urls: number;
  candidate_urls: CandidateUrl[];
  engines_queried: string[];
  saved_file_path?: string | null;
}

export interface FeedToScannerRequest {
  urls: string[];
  scope_grant_id?: string | null;
  auto_register_assets?: boolean;
  target_scanner?: 'all' | 'sqlmap' | 'practice_scripts' | string;
}

export interface FeedToScannerResponse {
  imported_count: number;
  target_ids: string[];
  targets_file_path: string;
  staged_terminal_cmd: string;
  message: string;
}

// Layer 2: Proxy Layer (Anonymity/Evasion) Types
export interface ProxyItem {
  raw_proxy: string;
  protocol: 'http' | 'https' | 'socks4' | 'socks5' | string;
  host: string;
  port: number;
  auth?: string | null;
  status: 'PENDING' | 'LIVE' | 'DEAD';
  latency_ms?: number | null;
  anonymity?: 'Elite' | 'Anonymous' | 'Transparent' | 'Unknown' | string;
  external_ip?: string | null;
  is_selected: boolean;
  error_message?: string | null;
  validated_at?: string | null;
}

export interface ProxyValidateRequest {
  proxies: string[];
  test_target_url?: string;
  timeout?: number;
}

export interface ProxyValidateResponse {
  total_tested: number;
  live_count: number;
  dead_count: number;
  average_latency_ms?: number | null;
  results: ProxyItem[];
}

export interface ProxySaveRequest {
  proxies: string[];
  filename?: string;
  only_live?: boolean;
}

export interface ProxySaveResponse {
  filename: string;
  file_path: string;
  saved_count: number;
  message: string;
}

export interface ProxyPoolConfig {
  is_enabled: boolean;
  rotation_strategy: 'round-robin' | 'random' | 'least-latency' | string;
  active_proxies: string[];
  total_active: number;
  file_path?: string | null;
}

export interface ProxyPreset {
  name: string;
  proxy: string;
  description: string;
}

// Layer 3: Scanning and Classification Types
export type Layer3TabCategory = 'queue' | 'exploitables' | 'injectables' | 'non_injectables' | 'trash';

export interface ClassifiedTarget {
  id: string;
  url: string;
  host: string;
  http_method: string;
  parameter?: string | null;
  category: Layer3TabCategory | string;
  status_code?: number | null;
  response_time_ms?: number | null;
  database_type?: string | null;
  database_version?: string | null;
  database_user?: string | null;
  heuristic_title?: string | null;
  evidence_snippet?: string | null;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  sqlmap_cmd?: string | null;
  tested_at?: string | null;
}

export interface DorkFileInfo {
  filename: string;
  file_path: string;
  total_lines: number;
  preview: string[];
}

export interface Layer3ScanRequest {
  dork_filename?: string;
  dork_lines?: string[];
  urls?: string[];
  target_domain?: string;
  search_engine?: string;
  max_urls_per_dork?: number;
  use_proxy_pool?: boolean;
  test_depth?: 'fast' | 'standard' | 'deep' | string;
}

export interface Layer3ScanResponse {
  scan_id: string;
  total_scanned: number;
  queue_count: number;
  exploitables_count: number;
  injectables_count: number;
  non_injectables_count: number;
  trash_count: number;
  results: ClassifiedTarget[];
  search_engine_used: string;
  proxy_used?: string | null;
  completed_at: string;
}

export interface Layer3Summary {
  total_count: number;
  queue_count: number;
  exploitables_count: number;
  injectables_count: number;
  non_injectables_count: number;
  trash_count: number;
  items: ClassifiedTarget[];
}

export type InjectionTechnique = 'auto' | 'boolean' | 'time_based' | 'error_based' | 'union';
export type ExploitationAction = 'fingerprint' | 'blind_sqli' | 'schema_dump' | 'file_dump';

export interface DatabaseChannelInfo {
  is_connected: boolean;
  technique_determined: string;
  technique_label: string;
  payload_used: string;
  dbms_type: string;
  dbms_version: string;
  current_user: string;
  current_db: string;
  server_hostname?: string;
  is_dba: boolean;
  channel_stability: string;
  established_at?: string;
}

export interface SchemaTable {
  name: string;
  row_count: number;
  columns: string[];
  sample_rows: Record<string, any>[];
}

export interface SchemaDatabase {
  name: string;
  is_current: boolean;
  table_count: number;
  tables: SchemaTable[];
}

export interface DumpedFile {
  path: string;
  size_bytes: number;
  method: string;
  content_snippet: string;
  is_sensitive: boolean;
  retrieved_at: string;
}

export interface Layer4ExploitRequest {
  target_url: string;
  http_method?: string;
  parameter?: string;
  technique?: InjectionTechnique | string;
  action?: ExploitationAction | string;
  target_database?: string;
  target_table?: string;
  target_file_path?: string;
  blind_expression?: string;
  use_proxy_pool?: boolean;
}

export interface Layer4ExploitResponse {
  execution_id: string;
  target_url: string;
  parameter: string;
  technique_selected: string;
  action_executed: string;
  channel: DatabaseChannelInfo;
  blind_result?: {
    expression: string;
    extracted_value: string;
    queries_executed: number;
    time_elapsed_ms: number;
    bisection_trace: Array<{ position: number; char: string; ascii: number; queries: number }>;
  } | null;
  schema_databases: SchemaDatabase[];
  dumped_files: DumpedFile[];
  sqlmap_command: string;
  execution_logs: string[];
  proxy_used?: string | null;
  completed_at: string;
}

// Layer 5: Hierarchical Database Enumeration & Data Dump Interfaces
export interface Layer5ColumnInfo {
  name: string;
  data_type: string;
  is_primary_key: boolean;
  is_nullable: boolean;
  sample_value?: string | null;
}

export interface Layer5TableInfo {
  name: string;
  database_name: string;
  estimated_rows: number;
  column_count: number;
  columns?: Layer5ColumnInfo[];
  is_sensitive?: boolean;
}

export interface Layer5DatabaseInfo {
  name: string;
  is_current: boolean;
  table_count: number;
  tables?: Layer5TableInfo[];
}

export interface Layer5EnumRequest {
  target_url: string;
  parameter?: string;
  http_method?: string;
  action: 'get_databases' | 'get_tables' | 'get_columns' | 'dump_records';
  database_name?: string;
  table_name?: string;
  selected_columns?: string[];
  limit?: number;
  offset?: number;
  use_proxy_pool?: boolean;
}

export interface Layer5EnumResponse {
  execution_id: string;
  target_url: string;
  parameter: string;
  action_executed: string;
  current_database?: string | null;
  databases: Layer5DatabaseInfo[];
  tables: Layer5TableInfo[];
  columns: Layer5ColumnInfo[];
  records: Record<string, any>[];
  total_records: number;
  limit: number;
  offset: number;
  sqlmap_command: string;
  execution_logs: string[];
  proxy_used?: string | null;
  completed_at: string;
}

// Layer 6: Data Extraction & Export Interfaces
export interface Layer6DumpRequest {
  target_url: string;
  parameter?: string;
  http_method?: string;
  database_name: string;
  table_name: string;
  selected_columns?: string[];
  limit?: number;
  offset?: number;
  use_proxy_pool?: boolean;
}

export interface Layer6DumpResponse {
  execution_id: string;
  target_url: string;
  parameter: string;
  database_name: string;
  table_name: string;
  selected_columns: string[];
  records: Record<string, any>[];
  total_records: number;
  limit: number;
  offset: number;
  sqlmap_command: string;
  execution_logs: string[];
  proxy_used?: string | null;
  txt_export_preview: string;
  xml_export_preview: string;
  completed_at: string;
}

export interface Layer6ExportRequest {
  format: 'txt' | 'xml' | 'csv' | 'json';
  database_name: string;
  table_name: string;
  columns: string[];
  records: Record<string, any>[];
  target_url?: string;
}

export interface Layer6ExportResponse {
  format: string;
  filename: string;
  content: string;
  mime_type: string;
  record_count: number;
  size_bytes: number;
}

// ============================================================================
// Path Finder (Authorized Endpoint Discovery) Interfaces
// ============================================================================

export type PathFinderStatus = 'PENDING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'CANCELLED' | 'FAILED';
export type PathFinderMode = 'QUICK' | 'AGGRESSIVE' | 'PASSIVE' | 'EXHAUSTIVE' | 'RECURSIVE';

export interface PathFinderScanCreate {
  target_id: string;
  user_id?: string;
  mode?: PathFinderMode;
  config_json?: Record<string, any>;
}

export interface PathFinderScanUpdateStatus {
  status: PathFinderStatus;
  progress_percent?: number;
}

export interface DiscoveredPath {
  id: string;
  scan_id: string;
  path: string;
  full_url: string;
  status_code: number;
  content_length?: number | null;
  content_type?: string | null;
  redirect_url?: string | null;
  response_time_ms?: number | null;
  discovered_at: string;
}

export interface PathFinderScan {
  id: string;
  target_id: string;
  user_id?: string | null;
  mode: PathFinderMode | string;
  config_json: Record<string, any>;
  status: PathFinderStatus;
  progress_percent: number;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
  total_discovered_paths: number;
  requests_per_second?: number;
  discovered_paths?: DiscoveredPath[];
}









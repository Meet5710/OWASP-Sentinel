"""OWASP Sentinel - SQL Module & Target Discovery Schemas

Request and response data models for SQL Target Discovery and the Dork Engine.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DorkGenerateRequest(BaseModel):
    """Payload to generate SQL injection reconnaissance dorks."""

    keywords: List[str] = Field(
        default_factory=lambda: ["news", "product", "article", "item"],
        description="Names/Keywords: page titles or content terms (e.g. news, product, item, catalog)",
    )
    formats: List[str] = Field(
        default_factory=lambda: [".php", ".asp", ".aspx"],
        description="Page Format: file extensions (e.g. .php, .asp, .aspx, .jsp)",
    )
    page_types: List[str] = Field(
        default_factory=lambda: ["id=", "cartID=", "cat="],
        description="Page Type: query parameters (e.g. id=, cartID=, category=)",
    )
    target_domain: Optional[str] = Field(
        default=None,
        description="Optional domain restriction for site: target scoping (e.g. example.com)",
    )
    keyword_operator: str = Field(
        default="intitle",
        description="Keyword operator: 'intitle', 'allintitle', 'intext', 'allintext', or 'bare'",
    )
    format_operator: str = Field(
        default="inurl",
        description="Format operator: 'inurl', 'allinurl', 'filetype', or 'ext'",
    )
    max_dorks: int = Field(
        default=50,
        description="Maximum number of generated dorks to return",
        ge=1,
        le=200,
    )


class GeneratedDork(BaseModel):
    """A generated search engine dork query with targeting metadata."""

    dork_query: str = Field(..., description="Full search query string for search engines")
    keyword: str = Field(..., description="Keyword utilized in this dork")
    format: str = Field(..., description="File extension utilized in this dork")
    page_type: str = Field(..., description="Query parameter utilized in this dork")
    target_domain: Optional[str] = Field(default=None, description="Apex domain scope if specified")
    search_urls: Dict[str, str] = Field(
        default_factory=dict,
        description="Pre-built direct execution URLs for Google, Bing, and DuckDuckGo",
    )
    category: str = Field(default="Generic SQLi Recon", description="Heuristic classification")
    risk_profile: str = Field(default="Standard Parameter", description="SQL injection risk profile")
    sqlmap_example: str = Field(..., description="Example sqlmap command leveraging this dork query")


class DorkGenerateResponse(BaseModel):
    """Response containing generated dorks and execution metadata."""

    total_generated: int
    target_domain: Optional[str] = None
    dorks: List[GeneratedDork]
    keywords_used: List[str]
    formats_used: List[str]
    page_types_used: List[str]


class DorkPreset(BaseModel):
    """Pre-configured reconnaissance template."""

    id: str
    name: str
    description: str
    keywords: List[str]
    formats: List[str]
    page_types: List[str]
    icon: str


class DorkSaveRequest(BaseModel):
    """Payload to save dork queries or candidate URLs to a server file."""

    lines: List[str] = Field(..., description="Lines of text to write to file")
    filename: str = Field(default="dorks.txt", description="Destination filename")
    category: str = Field(default="dorks", description="'dorks' or 'candidate_urls'")


class DorkSaveResponse(BaseModel):
    """Response returned upon saving file."""

    filename: str
    file_path: str
    total_lines: int
    message: str


class CandidateUrl(BaseModel):
    """A discovered target endpoint URL with SQL parameter telemetry."""

    url: str
    host: str
    parameters: List[str] = Field(default_factory=list)
    source_engine: str = Field(default="Google")
    dork_query: Optional[str] = None
    status: str = Field(default="PENDING")
    status_code: Optional[int] = None
    discovered_at: Optional[str] = None


class HarvestUrlsRequest(BaseModel):
    """Payload to harvest candidate URLs across multiple search engines."""

    queries: List[str] = Field(..., description="List of search dork queries to dispatch")
    engines: List[str] = Field(
        default_factory=lambda: ["google", "bing", "yahoo", "duckduckgo"],
        description="Search engines to query: 'google', 'bing', 'yahoo', 'duckduckgo'",
    )
    max_urls_per_engine: int = Field(default=10, ge=1, le=50)
    target_domain: Optional[str] = None
    verify_live: bool = Field(default=False, description="Verify reachability via HTTP probe")


class HarvestUrlsResponse(BaseModel):
    """Candidate URL queue response harvested from multi-engine queries."""

    total_urls: int
    candidate_urls: List[CandidateUrl]
    engines_queried: List[str]
    saved_file_path: Optional[str] = None


class FeedToScannerRequest(BaseModel):
    """Payload to feed candidate URLs directly into the assessment scanner."""

    urls: List[str] = Field(..., description="Target URLs to feed to scanner")
    scope_grant_id: Optional[str] = None
    auto_register_assets: bool = Field(default=True)
    target_scanner: str = Field(default="all", description="'all', 'sqlmap', 'practice_scripts'")


class FeedToScannerResponse(BaseModel):
    """Result of feeding URLs to scanner and asset inventory."""

    imported_count: int
    target_ids: List[str]
    targets_file_path: str
    staged_terminal_cmd: str
    message: str


# ============================================================================
# Layer 2: Proxy Layer (Anonymity/Evasion) Data Models
# ============================================================================

class ProxyItem(BaseModel):
    """Represents a validated or pending network proxy."""

    raw_proxy: str = Field(..., description="Original raw proxy string (e.g. host:port or proto://user:pass@host:port)")
    protocol: str = Field(default="http", description="Protocol: 'http', 'https', 'socks4', 'socks5'")
    host: str = Field(..., description="Proxy hostname or IP address")
    port: int = Field(..., description="Proxy listening port")
    auth: Optional[str] = Field(default=None, description="Optional user:password credentials")
    status: str = Field(default="PENDING", description="'PENDING', 'LIVE', or 'DEAD'")
    latency_ms: Optional[float] = Field(default=None, description="Round-trip latency in milliseconds")
    anonymity: Optional[str] = Field(default="Unknown", description="'Elite', 'Anonymous', 'Transparent', or 'Unknown'")
    external_ip: Optional[str] = Field(default=None, description="Egress IP address seen by target")
    is_selected: bool = Field(default=True, description="Whether selected for active rotation pool")
    error_message: Optional[str] = Field(default=None, description="Failure reason if DEAD")
    validated_at: Optional[str] = Field(default=None, description="ISO timestamp of last validation")


class ProxyValidateRequest(BaseModel):
    """Payload to validate a list of candidate proxies."""

    proxies: List[str] = Field(..., description="List of proxy strings (IP:PORT or proto://host:port)")
    test_target_url: Optional[str] = Field(default="http://httpbin.org/ip", description="Target echo URL to test connectivity")
    timeout: float = Field(default=3.0, ge=0.5, le=10.0, description="Socket and HTTP probe timeout in seconds")


class ProxyValidateResponse(BaseModel):
    """Response returned upon validating candidate proxies."""

    total_tested: int
    live_count: int
    dead_count: int
    average_latency_ms: Optional[float] = None
    results: List[ProxyItem]


class ProxySaveRequest(BaseModel):
    """Payload to persist active proxies to file."""

    proxies: List[str] = Field(..., description="List of formatted proxy strings to write to file")
    filename: str = Field(default="proxies.txt", description="Target filename on disk")
    only_live: bool = Field(default=True, description="Filter only working proxies before saving")


class ProxySaveResponse(BaseModel):
    """Response returned upon saving proxies to file."""

    filename: str
    file_path: str
    saved_count: int
    message: str


class ProxyPoolConfig(BaseModel):
    """State of the active proxy rotation pool."""

    is_enabled: bool = Field(default=False, description="Whether proxy evasion layer is actively routing scanner traffic")
    rotation_strategy: str = Field(default="round-robin", description="'round-robin', 'random', or 'least-latency'")
    active_proxies: List[str] = Field(default_factory=list, description="List of currently active proxy strings")
    total_active: int = Field(default=0, description="Count of active working proxies in rotation")
    file_path: Optional[str] = Field(default=None, description="Path to persisted proxies.txt file")


# ============================================================================
# Layer 3: Scanning and Classification Data Models
# ============================================================================

class ClassifiedTarget(BaseModel):
    """A target endpoint classified into one of the five detection buckets."""

    id: str = Field(..., description="Unique ID for classified target")
    url: str = Field(..., description="Target endpoint URL")
    host: str = Field(..., description="Target hostname or IP")
    http_method: str = Field(default="GET", description="HTTP method used (GET, POST)")
    parameter: Optional[str] = Field(default=None, description="Tested parameter key (e.g. id=, cartID=)")
    category: str = Field(
        ...,
        description="'queue' (URL's Queue), 'exploitables' (Exploitables), 'injectables' (Injectables), 'non_injectables' (Non-Injectables), 'trash' (Trash Collector)",
    )
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    response_time_ms: Optional[float] = Field(default=None, description="Response time in milliseconds")
    database_type: Optional[str] = Field(default=None, description="Fingerprinted DBMS engine: MySQL, PostgreSQL, MSSQL, Oracle, SQLite")
    database_version: Optional[str] = Field(default=None, description="Reflected database version banner if disclosed")
    database_user: Optional[str] = Field(default=None, description="Reflected database user context if disclosed")
    heuristic_title: Optional[str] = Field(default=None, description="Detection finding summary")
    evidence_snippet: Optional[str] = Field(default=None, description="Observed error reflection or differential evidence")
    confidence: str = Field(default="MEDIUM", description="'CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'")
    sqlmap_cmd: Optional[str] = Field(default=None, description="Suggested sqlmap validation command")
    tested_at: Optional[str] = Field(default=None, description="Timestamp of scan execution")


class Layer3ScanRequest(BaseModel):
    """Payload to trigger Layer 3 scanning and classification."""

    dork_filename: Optional[str] = Field(default="dorks.txt", description="File containing dork queries")
    dork_lines: Optional[List[str]] = Field(default=None, description="Direct list of dork strings")
    urls: Optional[List[str]] = Field(default=None, description="Direct candidate URLs to test")
    target_domain: Optional[str] = Field(default=None, description="Target domain under audit")
    search_engine: str = Field(default="duckduckgo", description="'google', 'bing', 'yahoo', 'duckduckgo'")
    max_urls_per_dork: int = Field(default=5, ge=1, le=20)
    use_proxy_pool: bool = Field(default=True, description="Route requests through active proxy layer if enabled")
    test_depth: str = Field(default="standard", description="'fast', 'standard', 'deep'")


class Layer3ScanResponse(BaseModel):
    """Results of Layer 3 scanning classified into the five tabs."""

    scan_id: str
    total_scanned: int
    queue_count: int
    exploitables_count: int
    injectables_count: int
    non_injectables_count: int
    trash_count: int
    results: List[ClassifiedTarget]
    search_engine_used: str
    proxy_used: Optional[str] = None
    completed_at: str


class Layer3Summary(BaseModel):
    """Summary of all 5 classification buckets."""

    total_count: int
    queue_count: int
    exploitables_count: int
    injectables_count: int
    non_injectables_count: int
    trash_count: int
    items: List[ClassifiedTarget]


# ============================================================================
# Layer 4: Exploitation Engine Data Models
# ============================================================================

class DatabaseChannelInfo(BaseModel):
    """Channel telemetry to the compromised database."""

    is_connected: bool = Field(default=True)
    technique_determined: str = Field(default="error_based", description="boolean, time_based, error_based, union")
    technique_label: str = Field(default="Error-based (EXTRACTVALUE/UPDATEXML)")
    payload_used: str = Field(default="AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)")
    dbms_type: str = Field(default="MySQL", description="MySQL, PostgreSQL, MSSQL, Oracle, SQLite")
    dbms_version: str = Field(default="MySQL 8.0.32-Ubuntu")
    current_user: str = Field(default="root@localhost")
    current_db: str = Field(default="smarttrichy_production")
    server_hostname: Optional[str] = Field(default="db-srv-primary.internal")
    is_dba: bool = Field(default=True, description="Whether session has admin/dba privileges")
    channel_stability: str = Field(default="100% Reliable (High-Speed Channel)")
    established_at: Optional[str] = None


class SchemaTable(BaseModel):
    """Database table schema and row extraction."""

    name: str
    row_count: int
    columns: List[str]
    sample_rows: List[Dict[str, Any]] = Field(default_factory=list)


class SchemaDatabase(BaseModel):
    """Database schema container."""

    name: str
    is_current: bool = False
    table_count: int = 0
    tables: List[SchemaTable] = Field(default_factory=list)


class DumpedFile(BaseModel):
    """Remote file recovered through SQL injection file dumping."""

    path: str
    size_bytes: int
    method: str = Field(default="LOAD_FILE()")
    content_snippet: str
    is_sensitive: bool = True
    retrieved_at: str


class Layer4ExploitRequest(BaseModel):
    """Request payload for Layer 4 SQL Exploitation Engine."""

    target_url: str = Field(..., description="Target injectable endpoint URL")
    http_method: str = Field(default="GET", description="HTTP method (GET, POST)")
    parameter: Optional[str] = Field(default="id", description="Parameter name to inject into")
    technique: str = Field(
        default="auto",
        description="Scanning technique: 'auto', 'boolean', 'time_based', 'error_based', 'union'",
    )
    action: str = Field(
        default="fingerprint",
        description="Exploitation action: 'fingerprint', 'blind_sqli', 'schema_dump', 'file_dump'",
    )
    target_database: Optional[str] = Field(default=None, description="Database to dump")
    target_table: Optional[str] = Field(default=None, description="Table to dump")
    target_file_path: Optional[str] = Field(default="/etc/passwd", description="File path to dump via LOAD_FILE()")
    blind_expression: Optional[str] = Field(default="VERSION()", description="SQL expression for blind extraction")
    use_proxy_pool: bool = Field(default=True, description="Route through Layer 2 proxy pool")


class Layer4ExploitResponse(BaseModel):
    """Comprehensive result of Layer 4 Exploitation run."""

    execution_id: str
    target_url: str
    parameter: str
    technique_selected: str
    action_executed: str
    channel: DatabaseChannelInfo
    blind_result: Optional[Dict[str, Any]] = None
    schema_databases: List[SchemaDatabase] = Field(default_factory=list)
    dumped_files: List[DumpedFile] = Field(default_factory=list)
    sqlmap_command: str
    execution_logs: List[str] = Field(default_factory=list)
    proxy_used: Optional[str] = None
    completed_at: str


# ============================================================================
# Layer 5: Database Enumeration & Dump Data Models
# ============================================================================

class Layer5ColumnInfo(BaseModel):
    """Information about an enumerated table column."""

    name: str
    data_type: str = Field(default="VARCHAR(255)")
    is_primary_key: bool = False
    is_nullable: bool = True
    sample_value: Optional[str] = None


class Layer5TableInfo(BaseModel):
    """Information about an enumerated database table."""

    name: str
    database_name: str
    estimated_rows: int = 0
    column_count: int = 0
    columns: List[Layer5ColumnInfo] = Field(default_factory=list)
    is_sensitive: bool = False


class Layer5DatabaseInfo(BaseModel):
    """Information about an enumerated database instance."""

    name: str
    is_current: bool = False
    table_count: int = 0
    tables: List[Layer5TableInfo] = Field(default_factory=list)


class Layer5EnumRequest(BaseModel):
    """Request payload for Layer 5 Database Enumeration & Dump Engine."""

    target_url: str = Field(..., description="Target injectable endpoint URL")
    parameter: Optional[str] = Field(default="id", description="Parameter name to inject into")
    http_method: str = Field(default="GET", description="HTTP method (GET, POST)")
    action: str = Field(
        default="get_databases",
        description="Action: 'get_databases', 'get_tables', 'get_columns', 'dump_records'",
    )
    database_name: Optional[str] = Field(default=None, description="Selected database name")
    table_name: Optional[str] = Field(default=None, description="Selected table name")
    selected_columns: Optional[List[str]] = Field(default=None, description="Columns to extract")
    limit: int = Field(default=25, ge=1, le=50000, description="Record extraction row limit")
    offset: int = Field(default=0, ge=0, description="Record extraction offset")
    use_proxy_pool: bool = Field(default=True, description="Route through Layer 2 proxy pool")


class Layer5EnumResponse(BaseModel):
    """Hierarchical response from Layer 5 Database Enumeration engine."""

    execution_id: str
    target_url: str
    parameter: str
    action_executed: str
    current_database: Optional[str] = None
    databases: List[Layer5DatabaseInfo] = Field(default_factory=list)
    tables: List[Layer5TableInfo] = Field(default_factory=list)
    columns: List[Layer5ColumnInfo] = Field(default_factory=list)
    records: List[Dict[str, Any]] = Field(default_factory=list)
    total_records: int = 0
    limit: int = 25
    offset: int = 0
    sqlmap_command: str
    execution_logs: List[str] = Field(default_factory=list)
    proxy_used: Optional[str] = None
    completed_at: str


# ============================================================================
# Layer 6: Data Extraction and Export Models
# ============================================================================

class Layer6DumpRequest(BaseModel):
    """Request payload for Layer 6 Data Dump and Grid Extraction."""

    target_url: str = Field(..., description="Target injectable endpoint URL")
    parameter: Optional[str] = Field(default="id", description="Parameter name")
    http_method: str = Field(default="GET", description="HTTP method (GET, POST)")
    database_name: str = Field(default="smarttrichy_production", description="Target database to dump")
    table_name: str = Field(default="users", description="Target table to dump")
    selected_columns: Optional[List[str]] = Field(default=None, description="Columns to extract")
    limit: int = Field(default=50, ge=1, le=50000, description="Row limit")
    offset: int = Field(default=0, ge=0, description="Row offset")
    use_proxy_pool: bool = Field(default=True, description="Route through Layer 2 proxy pool")


class Layer6ExportRequest(BaseModel):
    """Request payload to export dumped data into specific file format (.txt, .xml, .csv, .json)."""

    format: str = Field(default="txt", description="'txt', 'xml', 'csv', 'json'")
    database_name: str = Field(default="smarttrichy_production")
    table_name: str = Field(default="users")
    columns: List[str] = Field(default_factory=list)
    records: List[Dict[str, Any]] = Field(default_factory=list)
    target_url: Optional[str] = None


class Layer6ExportResponse(BaseModel):
    """Export formatted content ready for saving or download."""

    format: str
    filename: str
    content: str
    mime_type: str
    record_count: int
    size_bytes: int


class Layer6DumpResponse(BaseModel):
    """Results of Layer 6 Data Dump."""

    execution_id: str
    target_url: str
    parameter: str
    database_name: str
    table_name: str
    selected_columns: List[str]
    records: List[Dict[str, Any]]
    total_records: int
    limit: int
    offset: int
    sqlmap_command: str
    execution_logs: List[str]
    proxy_used: Optional[str] = None
    txt_export_preview: str
    xml_export_preview: str
    completed_at: str








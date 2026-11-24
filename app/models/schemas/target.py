"""OWASP Sentinel - Target Schemas

Request and response data models for target validation, input normalization,
and scope authorization.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


class TargetValidationRequest(BaseModel):
    """Payload submitted to validate and sanitize a target before assessment."""

    target: str = Field(
        ...,
        description="Target URL, domain, subdomain, or IP/port (e.g. 'https://example.com:8443/app' or 'example.com')",
        min_length=1,
        max_length=2048,
        examples=["https://example.com", "example.com:8443", "203.0.113.5:8080"],
    )
    is_authorized: bool = Field(
        default=False,
        description="Explicit attestation that you possess legal authorization to assess this target",
    )
    authorization_notes: str | None = Field(
        default=None,
        description="Reference or justification for authorization (e.g. 'Scope Grant #2026-Q4')",
        max_length=500,
    )
    scope_grant_id: str | None = Field(
        default=None,
        description="Identifier linking this assessment to an authorized scope record",
        max_length=100,
    )
    allow_private_ips: bool = Field(
        default=False,
        description="Explicitly allow RFC 1918 / private IP addresses for internal lab/staging testing",
    )
    skip_dns_resolution: bool = Field(
        default=False,
        description="Skip live DNS resolution checks (useful for dry runs and offline testing)",
    )

    @field_validator("target")
    @classmethod
    def clean_target_string(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target string cannot be empty or whitespace only.")
        return cleaned


class TargetValidationResponse(BaseModel):
    """Normalized and security-validated representation of a target."""

    is_valid: bool = Field(..., description="Whether the target successfully passed validation")
    original_input: str = Field(..., description="The raw target string submitted")
    canonical_url: str = Field(..., description="Normalized canonical URL used for assessment")
    scheme: str = Field(..., description="Normalized protocol scheme (http or https)")
    host: str = Field(..., description="Canonical hostname or IP address")
    port: int = Field(..., description="TCP port number to assess")
    path: str = Field(..., description="Normalized URL path component")
    is_ip_address: bool = Field(..., description="True if target is an explicit IP address")
    resolved_ips: list[str] = Field(default_factory=list, description="Resolved IP addresses from DNS")
    is_private_ip: bool = Field(..., description="Whether the target resolves to a private or lab IP space")
    authorization_confirmed: bool = Field(..., description="Whether explicit authorization was verified")
    scope_grant_id: str | None = Field(default=None, description="Linked scope grant identifier if provided")
    security_warnings: list[str] = Field(default_factory=list, description="Advisories and non-fatal warnings")
    validated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when validation completed",
    )


class SubdomainDiscoveryRequest(BaseModel):
    """Request payload to discover and enumerate subdomains for an apex target domain."""

    domain: str = Field(
        ...,
        description="Target apex domain to enumerate (e.g. 'smarttrichy.in' or 'example.com')",
        examples=["smarttrichy.in", "acme.com", "gov.in"],
        min_length=3,
        max_length=255,
    )
    include_dns_probe: bool = Field(
        default=True,
        description="Whether to probe common subdomains via DNS wordlist",
    )
    include_cert_transparency: bool = Field(
        default=True,
        description="Whether to query public Certificate Transparency (crt.sh, CertSpotter) logs",
    )
    verify_live: bool = Field(
        default=True,
        description="Whether to test HTTP/HTTPS availability for discovered subdomains",
    )
    continuous_scan: bool = Field(
        default=False,
        description="Whether to execute progressive continuous multi-phase discovery",
    )
    deep_scan: bool = Field(
        default=True,
        description="Whether to execute unbounded adaptive target vocabulary and heuristic discovery",
    )
    include_permutations: bool = Field(
        default=True,
        description="Whether to generate recursive sub-subdomain permutations on discovered assets",
    )
    enable_live_scraping: bool = Field(
        default=True,
        description="Enable active live web scraping & JavaScript spidering across discovered assets",
    )
    scrape_depth: int = Field(
        default=2,
        description="Maximum recursion depth for active live web scraper (1=initial, 2=recursive)",
    )


class DiscoveredSubdomain(BaseModel):
    """Details of an individual discovered subdomain."""

    subdomain: str
    canonical_url: str
    ip_addresses: list[str] = Field(default_factory=list)
    is_live: bool = False
    scheme: str = "https"
    port: int = 443
    status_code: int | None = None
    response_time_ms: float | None = None
    server_banner: str | None = None
    page_title: str | None = None
    live_scraped: bool = False
    sources: list[str] = Field(default_factory=list)
    is_already_in_inventory: bool = False
    existing_asset_id: str | None = None


class SubdomainDiscoveryResponse(BaseModel):
    """Complete results for target subdomain discovery and reconnaissance."""

    target_domain: str
    total_discovered: int
    live_count: int
    dns_active_count: int = 0
    live_scraped_count: int = 0
    sources_summary: dict[str, int] = Field(default_factory=dict)
    subdomains: list[DiscoveredSubdomain]
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

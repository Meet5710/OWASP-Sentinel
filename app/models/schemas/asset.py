"""OWASP Sentinel - Authorized Asset Schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class AssetRegisterRequest(BaseModel):
    """Payload to register a new target asset into an approved scope inventory."""

    target: str = Field(
        ...,
        description="Target URL, domain, or IP (e.g. 'https://app.example.com:8443' or 'example.com')",
        min_length=1,
        max_length=2048,
    )
    scope_code: str = Field(
        ...,
        description="Scope code authorizing this asset (e.g. 'SCOPE-2026-APPSEC')",
        min_length=3,
        max_length=100,
    )
    is_authorized: bool = Field(
        default=True,
        description="Explicit attestation that you possess legal authorization to assess this target",
    )
    asset_type: str = Field(
        default="URL",
        description="Classification of asset: URL, DOMAIN, SUBDOMAIN, or IP",
    )
    skip_dns_resolution: bool = Field(
        default=False,
        description="Skip live DNS check (for offline/dry-run environments)",
    )


class AssetResponse(BaseModel):
    """Details of an authorized asset in the approved inventory."""

    id: str
    organization_id: str
    scope_grant_id: str
    scope_code: str | None = None
    target_input: str
    canonical_url: str
    host: str
    scheme: str
    port: int
    path: str
    asset_type: str
    is_ip_address: bool
    is_private_ip: bool
    resolved_ips: list[str]
    approval_status: str
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime


class AssetApprovalUpdateRequest(BaseModel):
    """Request to update an asset's approval status (Approve or Revoke)."""

    approval_status: str = Field(..., description="Target status: APPROVED, REVOKED, or PENDING")
    approved_by: str = Field(..., description="Identity of the administrator making the approval decision")
    reason: str | None = Field(default=None, description="Optional audit explanation")


class TargetAuthorizationCheckRequest(BaseModel):
    """Request to evaluate whether a target is currently authorized and within active scope."""

    target: str = Field(..., description="Target URL, host, or IP to test against authorization rules")
    scope_code: str | None = Field(default=None, description="Optional specific scope to evaluate against")


class TargetAuthorizationCheckResponse(BaseModel):
    """Assessment authorization clearance determination."""

    is_authorized: bool
    status: str
    reason: str
    asset_id: str | None = None
    scope_code: str | None = None
    canonical_url: str | None = None
    rate_limit_per_minute: int | None = None
    request_budget: int | None = None

"""OWASP Sentinel - Scan & Rule Schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanExecuteRequest(BaseModel):
    """Payload to trigger an on-demand security scan against an approved asset."""

    asset_id: str | None = Field(default=None, description="ID of the approved asset in the inventory")
    rule_ids: list[str] | None = Field(
        default=None, description="Optional subset of rule IDs to execute (runs all if omitted)"
    )


class TechnicalObservationResponse(BaseModel):
    """Details of a single technical weakness or vulnerability finding."""

    id: str
    scan_id: str
    target_id: str
    rule_id: str
    title: str
    technical_issue_type: str
    severity: str
    confidence: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str]
    created_at: datetime


class ScanJobResponse(BaseModel):
    """Execution status and summary metrics for an assessment run."""

    id: str
    target_id: str
    scope_grant_id: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_checks: int
    passed_checks: int
    failed_checks: int
    observations_count: int = 0
    error_message: str | None = None
    scan_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class RuleMetadataResponse(BaseModel):
    """Documentation and configuration metadata for a detection check."""

    rule_id: str
    name: str
    description: str
    why_it_matters: str
    evidence_description: str
    owasp_category_mappings: dict[str, str]
    required_permissions: str
    known_limitations: str
    potential_false_positives: str
    remediation_guidance: str
    references: list[str]
    severity: str = "MEDIUM"
    confidence: str = "HIGH"


class CategoryCoverageDetail(BaseModel):
    """Status of automated coverage for a single OWASP Top 10 category."""

    category_code: str
    category_title: str
    edition: str
    coverage_status: str  # AUTOMATED_CHECKS, MANUAL_REVIEW_REQUIRED, NO_IMPLEMENTED_DETECTION
    automated_rule_count: int
    rule_ids: list[str]
    rule_names: list[str]
    capabilities: list[str] = []
    limitations: list[str] = []


class CoverageMatrixResponse(BaseModel):
    """Comprehensive OWASP Top 10 automated coverage matrix."""

    edition: str
    total_categories: int
    categories_with_automated_rules: int
    categories_requiring_manual_review: int
    uncovered_categories: int
    coverage_matrix: list[CategoryCoverageDetail]

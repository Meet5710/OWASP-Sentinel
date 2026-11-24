"""OWASP Sentinel - Finding Schemas

Request and response schemas for managed findings, validation states,
and OWASP taxonomy category linkages.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_serializer, computed_field


class FindingCategoryMappingResponse(BaseModel):
    """Details of a single OWASP Top 10 category mapping associated with a finding."""

    id: str
    edition_identifier: str = ""
    category_identifier: str = ""
    owasp_edition: str = ""
    owasp_category_code: str = ""
    owasp_category_title: str = ""
    justification: str

    model_config = {"extra": "allow"}


class FindingResponse(BaseModel):
    """Detailed managed security finding record."""

    id: str
    target_id: str
    scan_id: str
    detection_rule_id: str

    @computed_field
    @property
    def rule_id(self) -> str:
        return self.detection_rule_id
    technical_issue_type: str
    title: str
    severity: str
    confidence: str
    validation_status: str
    first_seen_at: datetime
    last_seen_at: datetime
    evidence: dict[str, Any]
    remediation_recommendations: str
    references: list[str]
    status_history: list[dict[str, Any]] = Field(default_factory=list)
    category_mappings: list[FindingCategoryMappingResponse] = Field(default_factory=list)

    @field_serializer("first_seen_at", "last_seen_at")
    def serialize_datetime(self, dt: datetime, _info: Any) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class FindingStatusUpdateRequest(BaseModel):
    """Payload to transition a finding's validation status (e.g. to FALSE_POSITIVE or MITIGATED)."""

    validation_status: str = Field(
        ..., description="New validation status: POTENTIAL, CONFIRMED, FALSE_POSITIVE, or MITIGATED"
    )
    actor: str = Field(..., description="Identity of the auditor/engineer modifying the status")
    note: str | None = Field(default=None, description="Explanation or triage justification")


class OWASPCategoryCount(BaseModel):
    """Aggregation count and severity distribution for an OWASP category."""

    category_code: str
    category_title: str
    finding_count: int
    severity_breakdown: dict[str, int]


class OWASPFindingsSummaryResponse(BaseModel):
    """Summary representation of findings grouped across an OWASP edition."""

    edition: str
    total_findings: int
    category_summaries: list[OWASPCategoryCount]

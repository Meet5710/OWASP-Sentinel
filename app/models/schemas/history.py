"""OWASP Sentinel - Patch Verification & Posture History Schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PatchVerificationResponse(BaseModel):
    """Details of an automated remediation verification check."""

    id: str
    finding_id: str
    scan_id: str
    target_id: str
    verification_status: str  # REMEDIATED, STILL_VULNERABLE, REGRESSED, INCONCLUSIVE
    verified_at: datetime
    notes: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class FindingHistoryRecordResponse(BaseModel):
    """Historical security posture data point for charting trends over time."""

    id: str
    target_id: str
    scan_id: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    new_findings_count: int
    resolved_findings_count: int
    recurrent_findings_count: int
    recorded_at: datetime


class TargetPostureTimelineResponse(BaseModel):
    """Aggregated timeline metrics for visual trend reporting (e.g. Recharts dashboard)."""

    target_id: str
    canonical_url: str
    total_historical_assessments: int
    history_records: list[FindingHistoryRecordResponse]
    recent_verifications: list[PatchVerificationResponse]

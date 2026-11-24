"""OWASP Sentinel - Schedule Schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScheduleCreateRequest(BaseModel):
    """Payload to schedule recurring security assessments for an asset."""

    target_id: str = Field(..., description="ID of the approved asset to assess on a recurring schedule")
    frequency: str = Field(default="WEEKLY", description="Recurrence frequency: DAILY, WEEKLY, MONTHLY, or CRON")
    cron_expression: str | None = Field(default=None, description="Standard 5-part cron syntax if frequency is CRON")
    rule_ids: list[str] | None = Field(default=None, description="Optional subset of rules to execute")


class ScheduleUpdateRequest(BaseModel):
    """Payload to update recurrence or pause/resume a schedule."""

    frequency: str | None = Field(default=None, description="Updated frequency")
    cron_expression: str | None = Field(default=None, description="Updated cron expression")
    is_active: bool | None = Field(default=None, description="True to resume, False to pause")
    rule_ids: list[str] | None = Field(default=None, description="Updated rule IDs")


class ScheduleResponse(BaseModel):
    """Details of a configured recurring assessment schedule."""

    id: str
    target_id: str
    scope_grant_id: str
    frequency: str
    cron_expression: str | None = None
    is_active: bool
    next_run_at: datetime
    last_run_at: datetime | None = None
    last_scan_id: str | None = None
    rule_ids: list[str] = Field(default_factory=list)
    schedule_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

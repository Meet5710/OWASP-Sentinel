"""OWASP Sentinel - Common Schemas

Shared response and status models across the API.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy", description="Current service health status")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Runtime environment")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the health check",
    )


class ErrorResponse(BaseModel):
    """Structured error payload schema."""

    error: str = Field(..., description="Short error description")
    code: str = Field(..., description="Machine-readable error identifier")
    detail: str = Field(..., description="Detailed explanation of the error")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional context or diagnostics")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the error event",
    )

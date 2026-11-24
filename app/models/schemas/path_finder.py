"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) Schemas.

Pydantic models for scan creation, status tracking, filtering, and discovered endpoint serialization.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PathFinderStatus(str, Enum):
    """Execution status for an authorized path finder scan."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class PathFinderMode(str, Enum):
    """Enumeration mode for path discovery."""

    QUICK = "QUICK"
    AGGRESSIVE = "AGGRESSIVE"
    PASSIVE = "PASSIVE"
    EXHAUSTIVE = "EXHAUSTIVE"
    RECURSIVE = "RECURSIVE"


class PathFinderControlAction(str, Enum):
    """Allowed control actions on an active or running scan."""

    PAUSE = "pause"
    RESUME = "resume"
    CANCEL = "cancel"


class PathFinderControlRequest(BaseModel):
    """Payload to pause, resume, or cancel an active scan."""

    action: str = Field(..., description="Action to perform: 'pause', 'resume', or 'cancel'")


class PathFinderScanCreate(BaseModel):
    """Payload to initialize a new Path Finder scan."""

    target_id: str = Field(..., description="ID of the approved Authorized Asset in inventory")
    user_id: Optional[str] = Field(default=None, description="Optional ID of the initiating user")
    mode: PathFinderMode = Field(default=PathFinderMode.QUICK, description="Scan enumeration mode")
    config_json: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration parameters: wordlist, extensions, threads, timeout, custom_headers, status_filter",
    )


class PathFinderScanUpdateStatus(BaseModel):
    """Payload to transition scan state."""

    status: PathFinderStatus = Field(..., description="New scan status: PAUSED, RUNNING, CANCELLED, etc.")
    progress_percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)


class DiscoveredPathCreate(BaseModel):
    """Payload to record a newly discovered path/endpoint."""

    path: str = Field(..., description="Relative or absolute discovered URI path (e.g. /api/v1/admin)")
    full_url: str = Field(..., description="Fully resolved endpoint URL")
    status_code: int = Field(..., description="HTTP response status code")
    content_length: Optional[int] = Field(default=None, description="Response payload size in bytes")
    content_type: Optional[str] = Field(default=None, description="HTTP Content-Type header")
    redirect_url: Optional[str] = Field(default=None, description="Location header if 3xx redirect")
    response_time_ms: Optional[float] = Field(default=None, description="Latency of response in milliseconds")


class DiscoveredPathResponse(BaseModel):
    """Representation of an endpoint discovered during scanning."""

    id: str
    scan_id: str
    path: str
    full_url: str
    status_code: int
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    discovered_at: datetime

    class Config:
        from_attributes = True


class PathFinderScanResponse(BaseModel):
    """Overview summary of a Path Finder scan job."""

    id: str
    target_id: str
    user_id: Optional[str] = None
    mode: str
    config_json: Dict[str, Any]
    status: str
    progress_percent: float
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    total_discovered_paths: int = 0
    requests_per_second: Optional[float] = 0.0

    class Config:
        from_attributes = True


class PathFinderScanDetailResponse(PathFinderScanResponse):
    """Detailed scan information including discovered endpoints list."""

    discovered_paths: List[DiscoveredPathResponse] = []


class PaginatedPathFinderScanResponse(BaseModel):
    """Paginated collection of scan jobs."""

    items: List[PathFinderScanResponse]
    total: int
    limit: int
    offset: int

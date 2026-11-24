"""OWASP Sentinel - XSSSpect Assessment API Endpoint.

Provides scoped, authorized reflected XSS detection endpoints backed by the xssspect engine.
"""

import asyncio
from typing import Any, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.db.asset import AuthorizedAsset
from xssspect.scanner import scan_url

router = APIRouter()


class XSSpectScanRequest(BaseModel):
    """Request payload for initiating an authorized XSSSpect scan."""

    url: str = Field(..., description="Target URL with query parameters or base path")
    target_id: Optional[str] = Field(None, description="Authorized target asset UUID from inventory")
    parameters: Optional[List[str]] = Field(None, description="Optional parameter list to test if query string is omitted")
    payload_file: Optional[str] = Field(None, description="Path to optional custom probe payload file")
    delay: Optional[float] = Field(0.5, ge=0.0, le=10.0, description="Delay in seconds between probe executions")
    use_playwright: Optional[bool] = Field(True, description="Enable Playwright headless DOM execution check")
    detection_mode: Optional[str] = Field("STANDARD", description="Detection strategy: STANDARD, DEEP, or DOM")


class XSSpectFinding(BaseModel):
    """Individual probe finding record."""

    parameter: str
    payload: str
    executed: bool
    reflected: bool
    dialog_message: Optional[str] = None
    error: Optional[str] = None


class XSSpectScanResponse(BaseModel):
    """XSSSpect assessment result schema."""

    url: str
    target_id: Optional[str] = None
    parameters_tested: List[str] = []
    findings: List[XSSpectFinding] = []
    vulnerable: bool = False
    error: Optional[str] = None


@router.post(
    "/scan",
    response_model=XSSpectScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Authorized Reflected XSS Scan",
)
async def run_xssspect_scan(
    payload: XSSpectScanRequest,
    db: Session = Depends(get_db),
) -> XSSpectScanResponse:
    """Runs reflected XSS detection against an authorized target.

    Validates that the target URL or target_id belongs to an approved asset in
    the Authorized Target Inventory before dispatching the XSSSpect scanner engine.
    """
    raw_url = payload.url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"

    parsed = urlparse(raw_url)
    target_host = (parsed.hostname or "").lower()

    if not target_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL provided. A valid hostname is required.",
        )

    # 1. Scope Enforcement: verify asset authorization
    asset: Optional[AuthorizedAsset] = None
    if payload.target_id:
        asset = db.scalar(
            select(AuthorizedAsset).where(AuthorizedAsset.id == payload.target_id)
        )
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target asset '{payload.target_id}' not found in inventory.",
            )
    else:
        # Match by hostname
        assets = db.scalars(
            select(AuthorizedAsset).where(
                AuthorizedAsset.approval_status.in_(["APPROVED", None])
            )
        ).all()
        for a in assets:
            if a.host and (a.host.lower() == target_host or target_host.endswith(f".{a.host.lower()}")):
                asset = a
                break

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope clearance failed: Target '{target_host}' is not in the Authorized Target Inventory.",
        )

    # 2. Parameter Normalization
    scan_target_url = raw_url
    if not parsed.query and payload.parameters:
        clean_params = [p.strip() for p in payload.parameters if p.strip()]
        if clean_params:
            query_str = "&".join(f"{p}=test" for p in clean_params)
            sep = "&" if "?" in scan_target_url else "?"
            scan_target_url = f"{scan_target_url}{sep}{query_str}"

    # 3. Dispatch Scanner Engine in Worker Thread
    try:
        scan_delay = payload.delay if payload.delay is not None else 0.05
        result = await asyncio.to_thread(
            scan_url,
            url=scan_target_url,
            payload_file=payload.payload_file,
            delay=scan_delay,
            mode=payload.detection_mode,
        )
    except Exception as exc:
        return XSSpectScanResponse(
            url=scan_target_url,
            target_id=asset.id,
            error=str(exc),
            vulnerable=False,
        )

    # 4. Map & Return Structured Findings
    findings_list = [
        XSSpectFinding(
            parameter=f.get("parameter", ""),
            payload=f.get("payload", ""),
            executed=bool(f.get("executed", False)),
            reflected=bool(f.get("reflected", False)),
            dialog_message=f.get("dialog_message"),
            error=f.get("error"),
        )
        for f in result.get("findings", [])
    ]

    return XSSpectScanResponse(
        url=result.get("url", scan_target_url),
        target_id=asset.id,
        parameters_tested=result.get("parameters_tested", []),
        findings=findings_list,
        vulnerable=bool(result.get("vulnerable", False)),
        error=result.get("error"),
    )


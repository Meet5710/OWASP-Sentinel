"""OWASP Sentinel - Target Management & Input Validation Endpoints

Handles target verification, scope validation, and SSRF security controls.
"""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.exceptions import (
    SecurityRestrictionError,
    TargetValidationError,
    UnauthorizedTargetError,
)
from app.core.validator import TargetValidator
from app.db.session import get_db
from app.models.schemas.common import ErrorResponse
from app.models.schemas.target import (
    SubdomainDiscoveryRequest,
    SubdomainDiscoveryResponse,
    TargetValidationRequest,
    TargetValidationResponse,
)
from app.services.subdomain_service import SubdomainDiscoveryService

router = APIRouter()


@router.post(
    "/validate",
    response_model=TargetValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate Target Input & Enforce Scope Authorization",
    responses={
        status.HTTP_200_OK: {
            "description": "Target is valid, normalized, authorized, and compliant with SSRF safety policies.",
            "model": TargetValidationResponse,
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Syntactic validation error (e.g. malformed hostname, invalid port, unsupported scheme).",
            "model": ErrorResponse,
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Authorization denied or target violates SSRF / loopback restrictions.",
            "model": ErrorResponse,
        },
    },
)
async def validate_target(request: TargetValidationRequest) -> TargetValidationResponse:
    """Validate a candidate target URL, domain, or IP for security assessment.

    Enforces:
    - Explicit authorization attestation (`is_authorized: true`).
    - Protocol scheme restrictions (HTTP and HTTPS only).
    - TCP port limits (1-65535).
    - SSRF protections: blocks cloud metadata, loopback (localhost), and unauthorized RFC1918 private IPs.
    - Canonical URL normalization.
    """
    try:
        return TargetValidator.validate(request)
    except UnauthorizedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Unauthorized Target", "code": exc.code, "message": exc.message, "details": exc.details},
        ) from exc
    except SecurityRestrictionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Security Restriction Violation",
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Target Validation Error",
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc


@router.post(
    "/find-subdomains",
    response_model=SubdomainDiscoveryResponse,
    status_code=status.HTTP_200_OK,
    summary="Subdomain Finder & Reconnaissance Engine",
    description=(
        "Enumerate active and historic subdomains for a domain using Certificate Transparency logs, "
        "DNS wordlist probing, and live service verification."
    ),
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
    },
)
async def find_subdomains(
    request: SubdomainDiscoveryRequest,
    db: Session = Depends(get_db),
) -> SubdomainDiscoveryResponse:
    """Discover subdomains for an apex target domain."""
    try:
        return await SubdomainDiscoveryService.discover(request, db=db)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Subdomain Discovery Error", "message": str(exc)},
        ) from exc


@router.post(
    "/find-subdomains/stream",
    summary="Continuous Real-Time Subdomain Discovery Stream",
    description="Streams discovered subdomains progressive by phase using newline-delimited JSON.",
)
async def find_subdomains_stream(
    request: SubdomainDiscoveryRequest,
    db: Session = Depends(get_db),
):
    """Stream subdomain discoveries progressive by phase in real-time."""
    async def event_generator():
        try:
            async for event in SubdomainDiscoveryService.discover_stream(request, db=db):
                yield json.dumps(event) + "\n"
        except Exception as exc:
            yield json.dumps({"type": "error", "message": str(exc)}) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


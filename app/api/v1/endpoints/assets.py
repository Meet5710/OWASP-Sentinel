"""OWASP Sentinel - Authorized Asset API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException, UnauthorizedTargetError
from app.db.session import get_db
from app.models.schemas.asset import (
    AssetApprovalUpdateRequest,
    AssetRegisterRequest,
    AssetResponse,
    TargetAuthorizationCheckRequest,
    TargetAuthorizationCheckResponse,
)
from app.models.schemas.common import ErrorResponse
from app.services import asset_service

router = APIRouter()


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Target Asset Under Approved Scope",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
    },
)
def register_asset(
    request: AssetRegisterRequest,
    db: Session = Depends(get_db),
) -> AssetResponse:
    """Validate and register a target asset into the authorized inventory."""
    try:
        asset = asset_service.register_asset(db, request)
        return AssetResponse(
            id=asset.id,
            organization_id=asset.organization_id,
            scope_grant_id=asset.scope_grant_id,
            scope_code=asset.scope_grant.scope_code if asset.scope_grant else None,
            target_input=asset.target_input,
            canonical_url=asset.canonical_url,
            host=asset.host,
            scheme=asset.scheme,
            port=asset.port,
            path=asset.path,
            asset_type=asset.asset_type,
            is_ip_address=asset.is_ip_address,
            is_private_ip=asset.is_private_ip,
            resolved_ips=asset.resolved_ips,
            approval_status=asset.approval_status,
            approved_by=asset.approved_by,
            approved_at=asset.approved_at,
            created_at=asset.created_at,
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Unauthorized Target", "code": exc.code, "message": exc.message},
        ) from exc
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Asset Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.get(
    "",
    response_model=list[AssetResponse],
    summary="List Authorized Assets",
)
def list_assets(
    scope_code: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[AssetResponse]:
    """List approved assets in the inventory with optional scope and status filters."""
    assets = asset_service.list_assets(db, scope_code=scope_code, status=status)
    return [
        AssetResponse(
            id=a.id,
            organization_id=a.organization_id,
            scope_grant_id=a.scope_grant_id,
            scope_code=a.scope_grant.scope_code if a.scope_grant else None,
            target_input=a.target_input,
            canonical_url=a.canonical_url,
            host=a.host,
            scheme=a.scheme,
            port=a.port,
            path=a.path,
            asset_type=a.asset_type,
            is_ip_address=a.is_ip_address,
            is_private_ip=a.is_private_ip,
            resolved_ips=a.resolved_ips,
            approval_status=a.approval_status,
            approved_by=a.approved_by,
            approved_at=a.approved_at,
            created_at=a.created_at,
        )
        for a in assets
    ]


@router.patch(
    "/{asset_id}/approval",
    response_model=AssetResponse,
    summary="Update Asset Approval Status (Approve/Revoke)",
)
@router.post(
    "/{asset_id}/approval",
    response_model=AssetResponse,
    summary="Update Asset Approval Status (Approve/Revoke - POST alias)",
    include_in_schema=False,
)
@router.patch(
    "/{asset_id}/approve",
    response_model=AssetResponse,
    summary="Update Asset Approval Status (Approve/Revoke - /approve alias)",
    include_in_schema=False,
)
@router.post(
    "/{asset_id}/approve",
    response_model=AssetResponse,
    summary="Update Asset Approval Status (Approve/Revoke - /approve POST alias)",
    include_in_schema=False,
)
def update_approval(
    asset_id: str,
    request: AssetApprovalUpdateRequest,
    db: Session = Depends(get_db),
) -> AssetResponse:
    """Manually approve or revoke an asset's testing status."""
    try:
        asset = asset_service.update_asset_approval(db, asset_id, request)
        return AssetResponse(
            id=asset.id,
            organization_id=asset.organization_id,
            scope_grant_id=asset.scope_grant_id,
            scope_code=asset.scope_grant.scope_code if asset.scope_grant else None,
            target_input=asset.target_input,
            canonical_url=asset.canonical_url,
            host=asset.host,
            scheme=asset.scheme,
            port=asset.port,
            path=asset.path,
            asset_type=asset.asset_type,
            is_ip_address=asset.is_ip_address,
            is_private_ip=asset.is_private_ip,
            resolved_ips=asset.resolved_ips,
            approval_status=asset.approval_status,
            approved_by=asset.approved_by,
            approved_at=asset.approved_at,
            created_at=asset.created_at,
        )
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Asset Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.delete(
    "/bulk/by-domain",
    status_code=status.HTTP_200_OK,
    summary="Bulk Delete Assets by Domain",
)
def delete_assets_by_domain(
    domain: str,
    db: Session = Depends(get_db),
):
    """Bulk delete all assets belonging to a domain from inventory."""
    deleted_count = asset_service.delete_assets_by_domain(db, domain=domain)
    return {
        "status": "success",
        "deleted_count": deleted_count,
        "message": f"Successfully removed {deleted_count} assets matching domain '{domain}' from inventory.",
    }


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Asset from Authorized Inventory",
)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
):
    """Permanently remove an authorized asset from the inventory."""
    try:
        asset_service.delete_asset(db, asset_id)
        return {"status": "success", "message": f"Asset '{asset_id}' deleted successfully."}
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Asset Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/{asset_id}/scan",
    status_code=status.HTTP_201_CREATED,
    summary="Execute Assessment Against Asset (Direct subpath)",
    include_in_schema=False,
)
@router.post(
    "/{asset_id}/execute",
    status_code=status.HTTP_201_CREATED,
    summary="Execute Assessment Against Asset (Direct subpath)",
    include_in_schema=False,
)
async def scan_asset_directly(
    asset_id: str,
    db: Session = Depends(get_db),
):
    """Direct scanner execution endpoint on asset path."""
    from app.scanner.engine import ScannerEngine
    from app.models.schemas.scan import ScanJobResponse
    try:
        job = await ScannerEngine.execute_scan(db=db, asset_id=asset_id)
        return ScanJobResponse(
            id=job.id,
            target_id=job.target_id,
            scope_grant_id=job.scope_grant_id,
            status=job.status,
            started_at=job.started_at,
            completed_at=job.completed_at,
            total_checks=job.total_checks,
            passed_checks=job.passed_checks,
            failed_checks=job.failed_checks,
            observations_count=job.failed_checks,
            error_message=job.error_message,
            scan_metadata=job.scan_metadata,
            created_at=job.created_at,
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Scan Denied", "code": exc.code, "message": exc.message, "details": exc.details},
        ) from exc
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Scan Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/check-authorization",
    response_model=TargetAuthorizationCheckResponse,
    summary="Pre-Scan Target Authorization Clearance Check",
)
def check_authorization(
    request: TargetAuthorizationCheckRequest,
    db: Session = Depends(get_db),
) -> TargetAuthorizationCheckResponse:
    """Evaluate whether a target is approved and cleared for assessment within active scope."""
    return asset_service.check_target_authorization(db=db, target=request.target, scope_code=request.scope_code)

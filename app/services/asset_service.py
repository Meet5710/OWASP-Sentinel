"""OWASP Sentinel - Authorized Asset Service

Handles inventory registration, scope policy compliance, approval workflows,
and pre-scan authorization verification.
"""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException, UnauthorizedTargetError
from app.core.validator import TargetValidator
from app.models.db.asset import AuthorizedAsset
from app.models.schemas.asset import (
    AssetApprovalUpdateRequest,
    AssetRegisterRequest,
    TargetAuthorizationCheckResponse,
)
from app.models.schemas.target import TargetValidationRequest
from app.services.audit_service import record_audit_event
from app.services.scope_service import get_scope_by_code, is_scope_valid


def register_asset(db: Session, request: AssetRegisterRequest) -> AuthorizedAsset:
    """Validate and register a target asset under an approved scope grant."""
    if not request.is_authorized:
        raise UnauthorizedTargetError("Explicit authorization attestation is required to register an asset.")

    # 1. Lookup Scope Grant
    scope = get_scope_by_code(db, request.scope_code)
    if not scope:
        raise SentinelException(
            message=f"Scope grant '{request.scope_code}' was not found.",
            code="SCOPE_NOT_FOUND",
        )

    # 2. Verify Scope Window and Active Status
    is_valid, scope_reason = is_scope_valid(scope)
    if not is_valid:
        raise SentinelException(
            message=f"Scope '{scope.scope_code}' cannot accept targets: {scope_reason}",
            code="SCOPE_INACTIVE_OR_EXPIRED",
        )

    # 3. Validate Target with TargetValidator (enforcing SSRF rules & normalization)
    val_req = TargetValidationRequest(
        target=request.target,
        is_authorized=True,
        scope_grant_id=scope.scope_code,
        allow_private_ips=scope.allow_private_ips,
        skip_dns_resolution=request.skip_dns_resolution,
    )
    val_res = TargetValidator.validate(val_req)

    # 4. Check Scope Protocol Restrictions
    if val_res.scheme not in scope.allowed_protocols:
        raise SentinelException(
            message=f"Protocol '{val_res.scheme}' is not permitted by scope {scope.scope_code} (allowed: {scope.allowed_protocols}).",
            code="DISALLOWED_PROTOCOL",
        )

    # 5. Check Scope Port Restrictions
    if val_res.port not in scope.allowed_ports:
        raise SentinelException(
            message=f"Port {val_res.port} is not permitted by scope {scope.scope_code} (allowed: {scope.allowed_ports}).",
            code="DISALLOWED_PORT",
        )

    # 6. Check Subdomain Policy
    # Requirement: "Discovered subdomains must not automatically become approved scan targets."
    approval_status = "APPROVED"
    if request.asset_type.upper() == "SUBDOMAIN" and not scope.allow_subdomains:
        # Requires explicit manual administrator approval
        approval_status = "PENDING"

    # 7. Check for Duplicate Target under same scope
    stmt = (
        select(AuthorizedAsset)
        .where(AuthorizedAsset.scope_grant_id == scope.id)
        .where(AuthorizedAsset.canonical_url == val_res.canonical_url)
    )
    existing = db.scalars(stmt).first()
    if existing:
        return existing

    # 8. Create Authorized Asset Record
    asset = AuthorizedAsset(
        organization_id=scope.organization_id,
        scope_grant_id=scope.id,
        target_input=val_res.original_input,
        canonical_url=val_res.canonical_url,
        host=val_res.host,
        scheme=val_res.scheme,
        port=val_res.port,
        path=val_res.path,
        asset_type=request.asset_type.upper(),
        is_ip_address=val_res.is_ip_address,
        is_private_ip=val_res.is_private_ip,
        resolved_ips=val_res.resolved_ips,
        approval_status=approval_status,
        approved_by=scope.authorized_by if approval_status == "APPROVED" else None,
        approved_at=datetime.now(timezone.utc) if approval_status == "APPROVED" else None,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # 9. Audit Event
    record_audit_event(
        db=db,
        event_type="TARGET_REGISTERED",
        actor=scope.authorized_by,
        target_id=asset.id,
        scope_id=scope.id,
        description=f"Asset '{asset.canonical_url}' registered under scope {scope.scope_code} with status {approval_status}.",
        metadata={
            "canonical_url": asset.canonical_url,
            "host": asset.host,
            "port": asset.port,
            "approval_status": approval_status,
        },
    )

    return asset


def check_target_authorization(
    db: Session, target: str, scope_code: str | None = None
) -> TargetAuthorizationCheckResponse:
    """Pre-scan authorization check verifying whether target is approved and within valid scope."""
    try:
        # First normalize the input using TargetValidator (dry-run mode)
        val_req = TargetValidationRequest(
            target=target,
            is_authorized=True,
            skip_dns_resolution=True,
            allow_private_ips=True,
        )
        val_res = TargetValidator.validate(val_req)
    except Exception as exc:
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="INVALID_TARGET_SYNTAX",
            reason=f"Target syntax validation failed: {str(exc)}",
        )

    # Search for matching authorized asset
    # Prefer exact canonical_url match first
    stmt = select(AuthorizedAsset).where(AuthorizedAsset.canonical_url == val_res.canonical_url)
    assets = list(db.scalars(stmt).all())

    # If no exact URL match, fallback to host-level match for DOMAIN or IP asset types
    if not assets:
        stmt = select(AuthorizedAsset).where(
            (AuthorizedAsset.host == val_res.host) & (AuthorizedAsset.asset_type.in_(["DOMAIN", "IP"]))
        )
        assets = list(db.scalars(stmt).all())

    if not assets:
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="UNAUTHORIZED_TARGET",
            reason=f"Target '{target}' is not registered in the approved asset inventory.",
            canonical_url=val_res.canonical_url,
        )

    # If specific scope requested, filter for it
    target_asset: AuthorizedAsset | None = None
    for a in assets:
        if scope_code is None or a.scope_grant.scope_code == scope_code.strip().upper():
            target_asset = a
            break

    if not target_asset:
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="SCOPE_MISMATCH",
            reason=f"Target '{target}' is not registered under scope '{scope_code}'.",
            canonical_url=val_res.canonical_url,
        )

    # Verify Approval Status
    if target_asset.approval_status != "APPROVED":
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="APPROVAL_PENDING_OR_REVOKED",
            reason=f"Target approval status is '{target_asset.approval_status}'. Assessment requires APPROVED status.",
            asset_id=target_asset.id,
            canonical_url=target_asset.canonical_url,
        )

    # Verify Scope Validity
    scope = target_asset.scope_grant
    is_valid, scope_reason = is_scope_valid(scope)
    if not is_valid:
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="EXPIRED_SCOPE",
            reason=f"Linked scope '{scope.scope_code}' is not valid: {scope_reason}",
            asset_id=target_asset.id,
            scope_code=scope.scope_code,
            canonical_url=target_asset.canonical_url,
        )

    # Verify Port & Protocol
    if val_res.port not in scope.allowed_ports:
        return TargetAuthorizationCheckResponse(
            is_authorized=False,
            status="DISALLOWED_PORT",
            reason=f"Port {val_res.port} is outside permitted scope ports ({scope.allowed_ports}).",
            asset_id=target_asset.id,
            scope_code=scope.scope_code,
            canonical_url=target_asset.canonical_url,
        )

    return TargetAuthorizationCheckResponse(
        is_authorized=True,
        status="AUTHORIZED",
        reason="Target is approved, within active scope, and cleared for security assessment.",
        asset_id=target_asset.id,
        scope_code=scope.scope_code,
        canonical_url=target_asset.canonical_url,
        rate_limit_per_minute=scope.max_requests_per_minute,
        request_budget=scope.request_budget,
    )


def update_asset_approval(db: Session, asset_id: str, data: AssetApprovalUpdateRequest) -> AuthorizedAsset:
    """Manually approve or revoke an asset's testing status."""
    stmt = select(AuthorizedAsset).where(AuthorizedAsset.id == asset_id)
    asset = db.scalars(stmt).first()
    if not asset:
        raise SentinelException(f"Asset ID '{asset_id}' not found.", code="ASSET_NOT_FOUND")

    old_status = asset.approval_status
    asset.approval_status = data.approval_status.upper()
    asset.approved_by = data.approved_by
    asset.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(asset)

    record_audit_event(
        db=db,
        event_type="TARGET_APPROVAL_CHANGED",
        actor=data.approved_by,
        target_id=asset.id,
        scope_id=asset.scope_grant_id,
        description=f"Asset '{asset.canonical_url}' approval changed from {old_status} to {asset.approval_status}. Reason: {data.reason or 'None'}.",
        metadata={
            "old_status": old_status,
            "new_status": asset.approval_status,
            "reason": data.reason,
        },
    )

    return asset


def list_assets(db: Session, scope_code: str | None = None, status: str | None = None) -> list[AuthorizedAsset]:
    """Retrieve filtered list of authorized assets."""
    stmt = select(AuthorizedAsset)
    if scope_code:
        scope = get_scope_by_code(db, scope_code)
        if scope:
            stmt = stmt.where(AuthorizedAsset.scope_grant_id == scope.id)
        else:
            return []
    if status:
        stmt = stmt.where(AuthorizedAsset.approval_status == status.upper())
    return list(db.scalars(stmt).all())


def delete_asset(db: Session, asset_id: str, actor: str = "secops@sentinel.internal") -> bool:
    """Permanently delete an authorized asset and all associated findings and scan records."""
    stmt = select(AuthorizedAsset).where(AuthorizedAsset.id == asset_id)
    asset = db.scalars(stmt).first()
    if not asset:
        raise SentinelException(f"Asset ID '{asset_id}' not found.", code="ASSET_NOT_FOUND")

    url = asset.canonical_url
    scope_id = asset.scope_grant_id

    # Clean up dependent records to ensure clean SQLite cascade
    from app.models.db.finding import Finding, TechnicalObservation
    from app.models.db.history import FindingHistoryRecord, PatchVerification
    from app.models.db.scan import ScanJob
    from app.models.db.schedule import ScheduledScan

    db.query(TechnicalObservation).filter(TechnicalObservation.target_id == asset_id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.target_id == asset_id).delete(synchronize_session=False)
    db.query(ScanJob).filter(ScanJob.target_id == asset_id).delete(synchronize_session=False)
    db.query(ScheduledScan).filter(ScheduledScan.target_id == asset_id).delete(synchronize_session=False)
    db.query(FindingHistoryRecord).filter(FindingHistoryRecord.target_id == asset_id).delete(synchronize_session=False)
    db.query(PatchVerification).filter(PatchVerification.target_id == asset_id).delete(synchronize_session=False)

    db.delete(asset)
    db.commit()

    record_audit_event(
        db=db,
        event_type="ASSET_DELETED",
        actor=actor,
        target_id=asset_id,
        scope_id=scope_id,
        description=f"Asset '{url}' (ID: {asset_id}) was permanently removed from authorized inventory.",
        metadata={"deleted_url": url, "asset_id": asset_id},
    )
    return True


def delete_assets_by_domain(
    db: Session,
    domain: str,
    actor: str = "secops@sentinel.internal",
) -> int:
    """Permanently delete all authorized assets matching a given apex domain or subdomain."""
    norm_domain = domain.lower().strip().lstrip(".")
    stmt = select(AuthorizedAsset).where(
        (AuthorizedAsset.host == norm_domain) | AuthorizedAsset.host.endswith(f".{norm_domain}")
    )
    assets_to_delete = list(db.scalars(stmt).all())
    if not assets_to_delete:
        return 0

    asset_ids = [a.id for a in assets_to_delete]

    from app.models.db.finding import Finding, TechnicalObservation
    from app.models.db.history import FindingHistoryRecord, PatchVerification
    from app.models.db.scan import ScanJob
    from app.models.db.schedule import ScheduledScan

    for chunk_start in range(0, len(asset_ids), 500):
        chunk_ids = asset_ids[chunk_start : chunk_start + 500]
        db.query(TechnicalObservation).filter(TechnicalObservation.target_id.in_(chunk_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.target_id.in_(chunk_ids)).delete(synchronize_session=False)
        db.query(ScanJob).filter(ScanJob.target_id.in_(chunk_ids)).delete(synchronize_session=False)
        db.query(ScheduledScan).filter(ScheduledScan.target_id.in_(chunk_ids)).delete(synchronize_session=False)
        db.query(FindingHistoryRecord).filter(FindingHistoryRecord.target_id.in_(chunk_ids)).delete(synchronize_session=False)
        db.query(PatchVerification).filter(PatchVerification.target_id.in_(chunk_ids)).delete(synchronize_session=False)

    for a in assets_to_delete:
        db.delete(a)
    db.commit()

    record_audit_event(
        db=db,
        event_type="ASSETS_BULK_DELETED",
        actor=actor,
        description=f"Bulk removed {len(assets_to_delete)} assets matching domain '{domain}' from authorized inventory.",
        metadata={"domain": domain, "deleted_count": len(assets_to_delete)},
    )
    return len(assets_to_delete)



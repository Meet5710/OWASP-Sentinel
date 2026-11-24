"""OWASP Sentinel - Path Finder (Authorized Endpoint Discovery) Endpoints.

REST API for managing scans, controlling jobs, querying discovered endpoints,
and exporting reconnaissance data under authorized target assets.
"""

import asyncio
import csv
from datetime import datetime, timezone
import io
import json
from typing import List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import SecurityRestrictionError, TargetValidationError
from app.db.session import SessionLocal, get_db
from app.models.db.asset import AuthorizedAsset
from app.models.db.path_finder import DiscoveredPath, PathFinderScan
from app.models.schemas.path_finder import (
    DiscoveredPathCreate,
    DiscoveredPathResponse,
    PathFinderControlRequest,
    PathFinderMode,
    PathFinderScanCreate,
    PathFinderScanDetailResponse,
    PathFinderScanResponse,
    PathFinderScanUpdateStatus,
    PathFinderStatus,
)
from app.services.audit_service import record_audit_event
from app.services.path_finder_broadcaster import ScanEventBroadcaster, broadcaster
from app.services.path_finder_queue import enqueue_path_finder_scan
from app.services.path_finder_service import run_path_finder_scan_task, validate_target_ssrf_safety
from app.services.path_finder_state import state_store

router = APIRouter()


@router.post(
    "/scans",
    response_model=PathFinderScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initialize and Start Path Finder Scan",
    description=(
        "Registers an authorized endpoint discovery scan against an approved target asset, "
        "validates SSRF boundaries, and launches the non-blocking background discovery worker."
    ),
)
async def create_path_finder_scan(
    payload: PathFinderScanCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
) -> PathFinderScanResponse:
    # 1. Strict Scope Enforcement: target_id must exist in Authorized Target Inventory
    asset = db.scalar(select(AuthorizedAsset).where(AuthorizedAsset.id == payload.target_id))
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target asset with ID '{payload.target_id}' not found in authorized inventory.",
        )

    if asset.approval_status != "APPROVED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target '{asset.host}' is not APPROVED for security assessments (status: {asset.approval_status}).",
        )

    # 2. SSRF Protection: Resolve target host and verify no loopback/private/link-local addresses
    target_host = asset.host
    try:
        validate_target_ssrf_safety(
            target_host,
            allow_private=asset.is_private_ip,
            known_ips=asset.resolved_ips,
        )
    except SecurityRestrictionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "SSRF Protection Violation",
                "code": "SSRF_RESTRICTION_ERROR",
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Target DNS Resolution Error",
                "code": "DNS_RESOLUTION_ERROR",
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc

    # 3. Create persistent scan record in PENDING state
    scan = PathFinderScan(
        target_id=payload.target_id,
        user_id=payload.user_id,
        mode=payload.mode.value,
        config_json=payload.config_json,
        status=PathFinderStatus.PENDING.value,
        progress_percent=0.0,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 4. Audit Logging: Record PATH_FINDER_SCAN_START event
    client_ip = request.client.host if request.client else None
    record_audit_event(
        db=db,
        event_type="PATH_FINDER_SCAN_START",
        actor=payload.user_id or "system",
        target_id=payload.target_id,
        scope_id=asset.scope_grant_id,
        ip_address=client_ip,
        description=f"Path Finder scan '{scan.id}' started against target '{asset.host}' (mode: {payload.mode.value})",
        metadata={
            "scan_id": scan.id,
            "target_id": payload.target_id,
            "user_id": payload.user_id,
            "mode": payload.mode.value,
            "config_json": payload.config_json,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    # 5. Enqueue scan to background job queue (Celery/Redis or async worker pool)
    target_base_url = asset.canonical_url or f"https://{asset.host}"
    enqueue_path_finder_scan(
        scan_id=scan.id,
        base_url=target_base_url,
        mode=scan.mode,
        config=scan.config_json,
        background_tasks=background_tasks,
    )

    # Return created scan immediately with 201 Created
    return PathFinderScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        user_id=scan.user_id,
        mode=scan.mode,
        config_json=scan.config_json,
        status=scan.status,
        progress_percent=scan.progress_percent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        total_discovered_paths=0,
    )


@router.get(
    "/scans",
    response_model=List[PathFinderScanResponse],
    summary="List Scan History with Pagination",
    description="Returns scan history with pagination, ordered by latest creation.",
)
async def list_path_finder_scans(
    response: Response,
    target_id: Optional[str] = Query(None, description="Filter scans by target asset ID"),
    scan_status: Optional[PathFinderStatus] = Query(None, alias="status", description="Filter by status"),
    page: Optional[int] = Query(None, ge=1, description="Page number (1-based)"),
    page_size: Optional[int] = Query(None, ge=1, le=200, description="Page size"),
    limit: int = Query(50, ge=1, le=200, description="Items limit"),
    offset: int = Query(0, ge=0, description="Offset"),
    db: Session = Depends(get_db),
) -> List[PathFinderScanResponse]:
    # Calculate effective limit and offset
    if page is not None:
        effective_limit = page_size if page_size is not None else limit
        effective_offset = (page - 1) * effective_limit
    else:
        effective_limit = limit
        effective_offset = offset

    # Count total
    count_stmt = select(func.count(PathFinderScan.id))
    if target_id:
        count_stmt = count_stmt.where(PathFinderScan.target_id == target_id)
    if scan_status:
        count_stmt = count_stmt.where(PathFinderScan.status == scan_status.value)
    total_count = db.scalar(count_stmt) or 0

    # Query scans
    stmt = select(PathFinderScan)
    if target_id:
        stmt = stmt.where(PathFinderScan.target_id == target_id)
    if scan_status:
        stmt = stmt.where(PathFinderScan.status == scan_status.value)

    stmt = stmt.order_by(PathFinderScan.created_at.desc()).offset(effective_offset).limit(effective_limit)
    scans = db.scalars(stmt).all()

    # Pagination metadata in headers
    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-Limit"] = str(effective_limit)
    response.headers["X-Offset"] = str(effective_offset)

    results: List[PathFinderScanResponse] = []
    for s in scans:
        paths_count_stmt = select(func.count(DiscoveredPath.id)).where(DiscoveredPath.scan_id == s.id)
        paths_count = db.scalar(paths_count_stmt) or 0
        scan_metrics = state_store.get_metrics(s.id)
        rps = scan_metrics.get("requests_per_second", 0.0) if scan_metrics else 0.0
        results.append(
            PathFinderScanResponse(
                id=s.id,
                target_id=s.target_id,
                user_id=s.user_id,
                mode=s.mode,
                config_json=s.config_json,
                status=s.status,
                progress_percent=s.progress_percent,
                started_at=s.started_at,
                completed_at=s.completed_at,
                created_at=s.created_at,
                updated_at=s.updated_at,
                total_discovered_paths=paths_count,
                requests_per_second=rps,
            )
        )
    return results


@router.get(
    "/scans/{scan_id}",
    response_model=PathFinderScanDetailResponse,
    summary="Get Scan Metadata & Discovered Paths",
    description="Returns scan metadata and discovered paths, with filtering for status_code and search string.",
)
async def get_path_finder_scan(
    scan_id: str,
    status_code: Optional[int] = Query(None, description="Filter by HTTP status code"),
    search: Optional[str] = Query(None, description="Filter by path or full_url substring"),
    limit: int = Query(100, ge=1, le=1000, description="Max paths to return"),
    offset: int = Query(0, ge=0, description="Offset for paths list"),
    db: Session = Depends(get_db),
) -> PathFinderScanDetailResponse:
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    paths_stmt = select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)
    if status_code is not None:
        paths_stmt = paths_stmt.where(DiscoveredPath.status_code == status_code)
    if search:
        paths_stmt = paths_stmt.where(
            DiscoveredPath.path.ilike(f"%{search}%") | DiscoveredPath.full_url.ilike(f"%{search}%")
        )

    paths_stmt = paths_stmt.order_by(DiscoveredPath.discovered_at.desc()).offset(offset).limit(limit)
    paths = db.scalars(paths_stmt).all()

    total_paths_stmt = select(func.count(DiscoveredPath.id)).where(DiscoveredPath.scan_id == scan_id)
    total_count = db.scalar(total_paths_stmt) or 0
    scan_metrics = state_store.get_metrics(scan_id)
    rps = scan_metrics.get("requests_per_second", 0.0) if scan_metrics else 0.0

    return PathFinderScanDetailResponse(
        id=scan.id,
        target_id=scan.target_id,
        user_id=scan.user_id,
        mode=scan.mode,
        config_json=scan.config_json,
        status=scan.status,
        progress_percent=scan.progress_percent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        total_discovered_paths=total_count,
        requests_per_second=rps,
        discovered_paths=[DiscoveredPathResponse.model_validate(p) for p in paths],
    )


@router.get(
    "/scans/{scan_id}/stream",
    summary="Real-Time Server-Sent Events (SSE) Stream",
    description=(
        "Pushes real-time SSE events for a scan: newly discovered paths, "
        "progress percentage, requests/second, and status changes."
    ),
)
async def stream_path_finder_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    async def sse_event_generator():
        # 1. Initial snapshot event
        with SessionLocal() as s_db:
            current_scan = s_db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
            paths = s_db.scalars(
                select(DiscoveredPath)
                .where(DiscoveredPath.scan_id == scan_id)
                .order_by(DiscoveredPath.discovered_at.asc())
                .limit(500)
            ).all()

        cur_status = current_scan.status if current_scan else scan.status
        cur_progress = current_scan.progress_percent if current_scan else scan.progress_percent
        metrics = state_store.get_metrics(scan_id)

        snapshot_event = {
            "type": "snapshot",
            "scan_id": scan_id,
            "status": cur_status,
            "progress_percent": cur_progress,
            "requests_per_second": metrics.get("requests_per_second", 0.0),
            "total_discovered": len(paths),
            "paths": [
                {
                    "id": p.id,
                    "path": p.path,
                    "full_url": p.full_url,
                    "status_code": p.status_code,
                    "content_length": p.content_length,
                    "content_type": p.content_type,
                    "redirect_url": p.redirect_url,
                    "response_time_ms": p.response_time_ms,
                    "discovered_at": p.discovered_at.isoformat() if p.discovered_at else "",
                }
                for p in paths
            ],
        }
        yield ScanEventBroadcaster.format_sse("snapshot", snapshot_event)

        # If scan is already finalized, send final status and close
        if cur_status in (
            PathFinderStatus.COMPLETED.value,
            PathFinderStatus.FAILED.value,
            PathFinderStatus.CANCELLED.value,
        ):
            yield ScanEventBroadcaster.format_sse(
                "status_change",
                {
                    "type": "status_change",
                    "scan_id": scan_id,
                    "status": cur_status,
                    "progress_percent": cur_progress,
                },
            )
            return

        # 2. Subscribe to live broadcaster events
        q = await broadcaster.subscribe(scan_id)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event_msg = await asyncio.wait_for(q.get(), timeout=12.0)
                    evt_type = event_msg.get("type", "message")
                    yield ScanEventBroadcaster.format_sse(evt_type, event_msg)
                    if evt_type == "status_change" and event_msg.get("status") in (
                        PathFinderStatus.COMPLETED.value,
                        PathFinderStatus.FAILED.value,
                        PathFinderStatus.CANCELLED.value,
                    ):
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await broadcaster.unsubscribe(scan_id, q)

    return StreamingResponse(
        sse_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/scans/{scan_id}/ws")
@router.websocket("/scans/{scan_id}/stream/ws")
async def websocket_path_finder_scan(websocket: WebSocket, scan_id: str):
    """Bidirectional WebSocket streaming newly discovered paths, progress, requests/sec,
    and accepting live control commands (pause/resume/cancel)."""
    with SessionLocal() as db:
        scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
        if not scan:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        paths = db.scalars(
            select(DiscoveredPath)
            .where(DiscoveredPath.scan_id == scan_id)
            .order_by(DiscoveredPath.discovered_at.asc())
            .limit(500)
        ).all()
        cur_status = scan.status
        cur_progress = scan.progress_percent

    await websocket.accept()

    # Send initial snapshot
    metrics = state_store.get_metrics(scan_id)
    snapshot = {
        "type": "snapshot",
        "scan_id": scan_id,
        "status": cur_status,
        "progress_percent": cur_progress,
        "requests_per_second": metrics.get("requests_per_second", 0.0),
        "total_discovered": len(paths),
        "paths": [
            {
                "id": p.id,
                "path": p.path,
                "full_url": p.full_url,
                "status_code": p.status_code,
                "content_length": p.content_length,
                "content_type": p.content_type,
                "redirect_url": p.redirect_url,
                "response_time_ms": p.response_time_ms,
                "discovered_at": p.discovered_at.isoformat() if p.discovered_at else "",
            }
            for p in paths
        ],
    }
    await websocket.send_text(json.dumps(snapshot))

    # Subscribe to live events
    q = await broadcaster.subscribe(scan_id)

    async def _send_events():
        try:
            while True:
                msg = await q.get()
                await websocket.send_text(json.dumps(msg))
        except Exception:
            pass

    async def _receive_controls():
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                    action = payload.get("action", "").lower().strip()
                    if action in ("pause", "resume", "cancel"):
                        state_store.set_control_flag(scan_id, action.upper())
                        with SessionLocal() as db:
                            s = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
                            if s:
                                if action == "pause":
                                    s.status = PathFinderStatus.PAUSED.value
                                elif action == "resume":
                                    s.status = PathFinderStatus.RUNNING.value
                                elif action == "cancel":
                                    s.status = PathFinderStatus.CANCELLED.value
                                    s.completed_at = datetime.now(timezone.utc)
                                db.commit()
                        broadcaster.publish(scan_id, "status_change", {"status": action.upper()})
                except json.JSONDecodeError:
                    pass
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    sender_task = asyncio.create_task(_send_events())
    receiver_task = asyncio.create_task(_receive_controls())

    done, pending = await asyncio.wait(
        [sender_task, receiver_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()

    await broadcaster.unsubscribe(scan_id, q)


@router.post(
    "/scans/{scan_id}/control",
    response_model=PathFinderScanResponse,
    summary="Control Active Scan Execution (Pause, Resume, Cancel)",
    description="Signals the background scan worker to pause, resume, or cancel.",
)
async def control_path_finder_scan(
    scan_id: str,
    payload: PathFinderControlRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PathFinderScanResponse:
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    action = payload.action.lower().strip()

    if action == "pause":
        if scan.status not in (PathFinderStatus.RUNNING.value, PathFinderStatus.PENDING.value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot pause scan in status '{scan.status}'.",
            )
        scan.status = PathFinderStatus.PAUSED.value
        state_store.set_control_flag(scan_id, "PAUSED")

    elif action == "resume":
        if scan.status != PathFinderStatus.PAUSED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot resume scan in status '{scan.status}'.",
            )
        scan.status = PathFinderStatus.RUNNING.value
        state_store.set_control_flag(scan_id, "RUNNING")

    elif action == "cancel":
        if scan.status in (
            PathFinderStatus.COMPLETED.value,
            PathFinderStatus.CANCELLED.value,
            PathFinderStatus.FAILED.value,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan is already finalized (status: {scan.status}).",
            )
        scan.status = PathFinderStatus.CANCELLED.value
        scan.completed_at = datetime.now(timezone.utc)
        state_store.set_control_flag(scan_id, "CANCELLED")

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{payload.action}'. Supported actions: 'pause', 'resume', 'cancel'.",
        )

    db.commit()
    db.refresh(scan)

    # Audit Logging: Record control event (pause, resume, cancel)
    event_map = {
        "pause": ("PATH_FINDER_SCAN_PAUSE", f"Path Finder scan '{scan.id}' paused by user"),
        "resume": ("PATH_FINDER_SCAN_RESUME", f"Path Finder scan '{scan.id}' resumed by user"),
        "cancel": ("PATH_FINDER_SCAN_CANCEL", f"Path Finder scan '{scan.id}' cancelled by user"),
    }
    event_type, desc = event_map[action]
    client_ip = request.client.host if request.client else None
    record_audit_event(
        db=db,
        event_type=event_type,
        actor=scan.user_id or "system",
        target_id=scan.target_id,
        ip_address=client_ip,
        description=desc,
        metadata={
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "user_id": scan.user_id,
            "action": action,
            "config_json": scan.config_json,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    # Publish real-time status change to SSE and WebSocket listeners
    broadcaster.publish(scan_id, "status_change", {"status": scan.status})

    count_stmt = select(func.count(DiscoveredPath.id)).where(DiscoveredPath.scan_id == scan_id)
    count = db.scalar(count_stmt) or 0

    return PathFinderScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        user_id=scan.user_id,
        mode=scan.mode,
        config_json=scan.config_json,
        status=scan.status,
        progress_percent=scan.progress_percent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        total_discovered_paths=count,
    )


@router.get(
    "/scans/{scan_id}/export",
    summary="Export Discovered Endpoints as JSON or CSV",
    description="Streams discovered endpoints for a scan as either a CSV file or formatted JSON payload.",
)
async def export_path_finder_scan(
    scan_id: str,
    request: Request,
    format: str = Query("json", description="Export format: 'json' or 'csv'"),
    status_code: Optional[int] = Query(None, description="Filter exported paths by status code"),
    search: Optional[str] = Query(None, description="Filter exported paths by substring"),
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    export_format = format.lower().strip()

    # Audit Logging: Record export event
    client_ip = request.client.host if request.client else None
    record_audit_event(
        db=db,
        event_type="PATH_FINDER_SCAN_EXPORT",
        actor=scan.user_id or "system",
        target_id=scan.target_id,
        ip_address=client_ip,
        description=f"Path Finder scan results for '{scan.id}' exported as {export_format.upper()}",
        metadata={
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "user_id": scan.user_id,
            "format": export_format,
            "config_json": scan.config_json,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    stmt = select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)
    if status_code is not None:
        stmt = stmt.where(DiscoveredPath.status_code == status_code)
    if search:
        stmt = stmt.where(
            DiscoveredPath.path.ilike(f"%{search}%") | DiscoveredPath.full_url.ilike(f"%{search}%")
        )

    stmt = stmt.order_by(DiscoveredPath.discovered_at.asc())
    paths = db.scalars(stmt).all()

    export_format = format.lower().strip()
    if export_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "id",
                "path",
                "full_url",
                "status_code",
                "content_length",
                "content_type",
                "redirect_url",
                "response_time_ms",
                "discovered_at",
            ]
        )
        for p in paths:
            writer.writerow(
                [
                    p.id,
                    p.path,
                    p.full_url,
                    p.status_code,
                    p.content_length or "",
                    p.content_type or "",
                    p.redirect_url or "",
                    p.response_time_ms or "",
                    p.discovered_at.isoformat() if p.discovered_at else "",
                ]
            )

        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="pathfinder-scan-{scan_id}.csv"'},
        )

    elif export_format == "json":
        data = {
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "mode": scan.mode,
            "status": scan.status,
            "progress_percent": scan.progress_percent,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_records": len(paths),
            "paths": [
                {
                    "id": p.id,
                    "path": p.path,
                    "full_url": p.full_url,
                    "status_code": p.status_code,
                    "content_length": p.content_length,
                    "content_type": p.content_type,
                    "redirect_url": p.redirect_url,
                    "response_time_ms": p.response_time_ms,
                    "discovered_at": p.discovered_at.isoformat() if p.discovered_at else None,
                }
                for p in paths
            ],
        }
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f'attachment; filename="pathfinder-scan-{scan_id}.json"'},
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{format}'. Supported formats: 'json', 'csv'.",
        )


@router.patch(
    "/scans/{scan_id}/status",
    response_model=PathFinderScanResponse,
    summary="Update Scan Status & Progress",
)
async def update_scan_status(
    scan_id: str,
    payload: PathFinderScanUpdateStatus,
    db: Session = Depends(get_db),
) -> PathFinderScanResponse:
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    scan.status = payload.status.value
    if payload.progress_percent is not None:
        scan.progress_percent = payload.progress_percent

    if payload.status in (PathFinderStatus.COMPLETED, PathFinderStatus.CANCELLED, PathFinderStatus.FAILED):
        scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    count_stmt = select(func.count(DiscoveredPath.id)).where(DiscoveredPath.scan_id == scan_id)
    count = db.scalar(count_stmt) or 0

    return PathFinderScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        user_id=scan.user_id,
        mode=scan.mode,
        config_json=scan.config_json,
        status=scan.status,
        progress_percent=scan.progress_percent,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        total_discovered_paths=count,
    )


@router.get(
    "/scans/{scan_id}/paths",
    response_model=List[DiscoveredPathResponse],
    summary="List Discovered Paths (With Index-Optimized Filters)",
    description="Returns discovered endpoints for a scan with indexed filtering on status_code.",
)
async def list_discovered_paths(
    scan_id: str,
    status_code: Optional[int] = Query(None, description="Filter by HTTP status code (utilizes ix_discovered_paths_scan_status index)"),
    search: Optional[str] = Query(None, description="Filter by substring in path or full_url"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[DiscoveredPathResponse]:
    stmt = select(DiscoveredPath).where(DiscoveredPath.scan_id == scan_id)
    if status_code is not None:
        stmt = stmt.where(DiscoveredPath.status_code == status_code)
    if search:
        stmt = stmt.where(DiscoveredPath.path.ilike(f"%{search}%") | DiscoveredPath.full_url.ilike(f"%{search}%"))

    stmt = stmt.order_by(DiscoveredPath.discovered_at.desc()).offset(offset).limit(limit)
    paths = db.scalars(stmt).all()
    return [DiscoveredPathResponse.model_validate(p) for p in paths]


@router.post(
    "/scans/{scan_id}/paths",
    response_model=List[DiscoveredPathResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Batch Insert Discovered Endpoints",
)
async def record_discovered_paths(
    scan_id: str,
    payload: List[DiscoveredPathCreate],
    db: Session = Depends(get_db),
) -> List[DiscoveredPathResponse]:
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    entities: List[DiscoveredPath] = []
    for item in payload:
        p = DiscoveredPath(
            scan_id=scan_id,
            path=item.path,
            full_url=item.full_url,
            status_code=item.status_code,
            content_length=item.content_length,
            content_type=item.content_type,
            redirect_url=item.redirect_url,
            response_time_ms=item.response_time_ms,
        )
        entities.append(p)

    db.add_all(entities)
    db.commit()
    for e in entities:
        db.refresh(e)

    return [DiscoveredPathResponse.model_validate(e) for e in entities]


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Scan and Associated Discovered Endpoints",
)
async def delete_path_finder_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    scan = db.scalar(select(PathFinderScan).where(PathFinderScan.id == scan_id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    db.delete(scan)
    db.commit()
    return None

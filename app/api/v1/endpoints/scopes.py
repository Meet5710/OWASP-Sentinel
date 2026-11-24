"""OWASP Sentinel - Scope Grant API Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException
from app.db.session import get_db
from app.models.schemas.common import ErrorResponse
from app.models.schemas.scope import ScopeGrantCreate, ScopeGrantResponse
from app.services import scope_service

router = APIRouter()


@router.post(
    "",
    response_model=ScopeGrantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an Authorized Scope Grant",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
    },
)
def create_scope(
    request: ScopeGrantCreate,
    db: Session = Depends(get_db),
) -> ScopeGrantResponse:
    """Register an explicit security assessment scope grant defining permitted boundaries,
    validity dates, and rate limits."""
    try:
        scope = scope_service.create_scope_grant(db, request)
        return ScopeGrantResponse.from_orm_model(scope)
    except SentinelException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Scope Error", "code": exc.code, "message": exc.message},
        ) from exc


@router.get(
    "",
    response_model=list[ScopeGrantResponse],
    summary="List Scope Grants",
)
def list_scopes(
    active_only: bool = False,
    db: Session = Depends(get_db),
) -> list[ScopeGrantResponse]:
    """Retrieve all configured scope grants, optionally filtering for active ones only."""
    scopes = scope_service.list_scope_grants(db, active_only=active_only)
    return [ScopeGrantResponse.from_orm_model(s) for s in scopes]


@router.get(
    "/{scope_code}",
    response_model=ScopeGrantResponse,
    summary="Get Scope Grant Details",
)
def get_scope(
    scope_code: str,
    db: Session = Depends(get_db),
) -> ScopeGrantResponse:
    """Retrieve a specific scope grant by its unique code."""
    scope = scope_service.get_scope_by_code(db, scope_code)
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Scope '{scope_code}' not found."},
        )
    return ScopeGrantResponse.from_orm_model(scope)

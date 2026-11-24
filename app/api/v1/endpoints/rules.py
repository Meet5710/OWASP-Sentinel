"""OWASP Sentinel - Detection Rules & Coverage Matrix API Endpoints."""

from fastapi import APIRouter, HTTPException, status

from app.models.schemas.scan import CoverageMatrixResponse, RuleMetadataResponse
from app.scanner.registry import rule_registry

router = APIRouter()


@router.get(
    "",
    response_model=list[RuleMetadataResponse],
    summary="List Detection Rules & Technical Documentation",
)
def list_rules() -> list[RuleMetadataResponse]:
    """Retrieve all implemented detection rules with complete documentation:
    test scope, justification, evidence collected, OWASP mappings, and remediation."""
    rules = rule_registry.list_rules()
    return [RuleMetadataResponse(**r.to_metadata_dict()) for r in rules]


@router.get(
    "/coverage/matrix",
    response_model=CoverageMatrixResponse,
    summary="OWASP Top 10 Category Coverage Matrix",
)
@router.get(
    "/coverage-matrix",
    response_model=CoverageMatrixResponse,
    include_in_schema=False,
)
def get_coverage_matrix(edition: str = "2025") -> CoverageMatrixResponse:
    """Retrieve coverage matrix showing automated checks, partial coverage,
    manual-review requirements, and unimplemented categories."""
    return CoverageMatrixResponse(**rule_registry.get_coverage_matrix(edition=edition))


@router.get(
    "/{rule_id}",
    response_model=RuleMetadataResponse,
    summary="Get Rule Documentation by Rule ID",
)
def get_rule_details(rule_id: str) -> RuleMetadataResponse:
    """Retrieve detailed documentation and limitations for a single detection rule."""
    rule = rule_registry.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not Found", "message": f"Rule '{rule_id}' not found."},
        )
    return RuleMetadataResponse(**rule.to_metadata_dict())

"""OWASP Sentinel - Taxonomy & Ingestion Schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OWASPCategoryResponse(BaseModel):
    """Details of an official OWASP Top 10 category definition."""

    id: str
    category_code: str
    category_title: str
    category_description: str
    cwe_examples: list[str] = Field(default_factory=list)
    source_url: str
    content_hash: str
    display_order: int
    retrieval_timestamp: datetime | None = None


class OWASPEditionResponse(BaseModel):
    """Official OWASP Top 10 publication edition record."""

    id: str
    edition_identifier: str
    title: str
    publication_year: int
    publication_date: str | None = None
    source_url: str
    content_hash: str
    retrieval_timestamp: datetime
    is_latest: bool
    categories: list[OWASPCategoryResponse] = Field(default_factory=list)


class IngestionRunResponse(BaseModel):
    """Audit log of an OWASP taxonomy ingestion execution."""

    id: str
    source_url: str
    status: str
    editions_processed: int
    categories_updated: int
    categories_created: int
    content_hash: str
    requires_admin_review: bool
    categories_processed: int | None = None
    changes_detected: bool | None = None
    admin_review_required: bool | None = None
    error_message: str | None = None
    log_details: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    completed_at: datetime | None = None

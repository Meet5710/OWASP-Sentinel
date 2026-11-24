"""OWASP Sentinel - OWASP Taxonomy Ingestion Service

Scheduled and on-demand ingestion service to check official OWASP publications,
detect new editions or updated category definitions, validate and normalize records,
and store taxonomy data idempotently with audit tracking.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db.ingestion import IngestionRun
from app.models.db.taxonomy import OWASPCategory, OWASPEdition
from app.services.audit_service import record_audit_event
from app.taxonomy.official_editions import OFFICIAL_EDITIONS_DATA

logger = logging.getLogger(__name__)


def compute_sha256_hash(payload: Any) -> str:
    """Compute deterministic SHA-256 hash for versioning and change detection."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class TaxonomyIngestionService:
    """Ingests official OWASP Top 10 publications and maintains historical records."""

    PRIMARY_SOURCE_URL = "https://owasp.org/www-project-top-ten/"

    @classmethod
    def run_ingestion(
        cls,
        db: Session,
        feed_data: list[dict[str, Any]] | None = None,
        force_update: bool = False,
    ) -> IngestionRun:
        """Execute an ingestion cycle idempotently against official taxonomy sources."""
        feed = feed_data if feed_data is not None else OFFICIAL_EDITIONS_DATA
        overall_hash = compute_sha256_hash(feed)

        # 1. Initialize Ingestion Run Log
        run_record = IngestionRun(
            source_url=cls.PRIMARY_SOURCE_URL,
            status="RUNNING",
            content_hash=overall_hash,
            started_at=datetime.now(timezone.utc),
            log_details={"feed_editions_count": len(feed)},
        )
        db.add(run_record)
        db.commit()
        db.refresh(run_record)

        editions_processed = 0
        categories_created = 0
        categories_updated = 0
        changes_detected = False
        requires_review = False

        try:
            for ed_data in feed:
                ed_identifier = str(ed_data["edition_identifier"])
                ed_categories = ed_data.get("categories", [])
                edition_hash = compute_sha256_hash(ed_data)

                # Check if edition exists
                stmt = select(OWASPEdition).where(OWASPEdition.edition_identifier == ed_identifier)
                edition = db.scalars(stmt).first()

                if not edition:
                    # New Edition Published!
                    changes_detected = True
                    requires_review = True
                    edition = OWASPEdition(
                        edition_identifier=ed_identifier,
                        title=ed_data["title"],
                        publication_year=ed_data["publication_year"],
                        publication_date=ed_data.get("publication_date"),
                        source_url=ed_data["source_url"],
                        content_hash=edition_hash,
                        is_latest=ed_data.get("is_latest", False),
                        edition_metadata={"initial_ingestion": True},
                    )
                    db.add(edition)
                    db.flush()  # Generate edition.id for foreign keys

                    for cat_data in ed_categories:
                        cat_hash = compute_sha256_hash(cat_data)
                        category = OWASPCategory(
                            edition_id=edition.id,
                            category_code=cat_data["category_code"],
                            category_title=cat_data["category_title"],
                            category_description=cat_data["category_description"],
                            cwe_examples=cat_data.get("cwe_examples", []),
                            source_url=cat_data.get("source_url", edition.source_url),
                            content_hash=cat_hash,
                            display_order=cat_data.get("display_order", 1),
                        )
                        db.add(category)
                        categories_created += 1

                    record_audit_event(
                        db=db,
                        event_type="TAXONOMY_EDITION_INGESTED",
                        actor="System/IngestionService",
                        description=f"New official OWASP edition ingested: {edition.title} ({len(ed_categories)} categories).",
                        metadata={"edition": ed_identifier, "categories_count": len(ed_categories)},
                    )

                elif edition.content_hash != edition_hash or force_update:
                    # Content Updated Upstream!
                    changes_detected = True
                    requires_review = True
                    edition.title = ed_data["title"]
                    edition.publication_date = ed_data.get("publication_date")
                    edition.content_hash = edition_hash
                    edition.retrieval_timestamp = datetime.now(timezone.utc)
                    edition.is_latest = ed_data.get("is_latest", False)

                    # Update/Insert categories
                    for cat_data in ed_categories:
                        cat_code = cat_data["category_code"]
                        cat_hash = compute_sha256_hash(cat_data)

                        cat_stmt = select(OWASPCategory).where(
                            (OWASPCategory.edition_id == edition.id) & (OWASPCategory.category_code == cat_code)
                        )
                        cat = db.scalars(cat_stmt).first()

                        if cat:
                            if cat.content_hash != cat_hash or force_update:
                                cat.category_title = cat_data["category_title"]
                                cat.category_description = cat_data["category_description"]
                                cat.cwe_examples = cat_data.get("cwe_examples", [])
                                cat.source_url = cat_data.get("source_url", edition.source_url)
                                cat.content_hash = cat_hash
                                categories_updated += 1
                        else:
                            new_cat = OWASPCategory(
                                edition_id=edition.id,
                                category_code=cat_data["category_code"],
                                category_title=cat_data["category_title"],
                                category_description=cat_data["category_description"],
                                cwe_examples=cat_data.get("cwe_examples", []),
                                source_url=cat_data.get("source_url", edition.source_url),
                                content_hash=cat_hash,
                                display_order=cat_data.get("display_order", 1),
                            )
                            db.add(new_cat)
                            categories_created += 1

                    record_audit_event(
                        db=db,
                        event_type="TAXONOMY_EDITION_UPDATED",
                        actor="System/IngestionService",
                        description=f"OWASP edition '{edition.title}' updated with upstream changes.",
                        metadata={"edition": ed_identifier, "updated_categories": categories_updated},
                    )

                editions_processed += 1

            db.commit()

            # 2. Finalize Ingestion Run Record
            run_record.status = "CHANGES_DETECTED" if changes_detected else "NO_CHANGE"
            run_record.editions_processed = editions_processed
            run_record.categories_created = categories_created
            run_record.categories_updated = categories_updated
            run_record.requires_admin_review = requires_review
            run_record.completed_at = datetime.now(timezone.utc)
            run_record.log_details = {
                "changes_detected": changes_detected,
                "editions_processed": editions_processed,
                "categories_created": categories_created,
                "categories_updated": categories_updated,
                "source_hash": overall_hash,
            }
            db.commit()
            db.refresh(run_record)

            return run_record

        except Exception as exc:
            db.rollback()
            run_record.status = "FAILED"
            run_record.error_message = str(exc)
            run_record.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error(f"Taxonomy ingestion run failed: {exc}")
            return run_record

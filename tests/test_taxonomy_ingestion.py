"""OWASP Sentinel - OWASP Historical Taxonomy & Ingestion Tests (Phase 4)

Verifies official OWASP editions from 2003 to 2021, historical preservation,
idempotent ingestion, change detection, and audit logging.
"""

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db.taxonomy import OWASPCategory, OWASPEdition
from app.services.ingestion_service import TaxonomyIngestionService
from app.taxonomy.official_editions import OFFICIAL_EDITIONS_DATA


class TestHistoricalTaxonomyIntegrity:
    """Verifies official published editions and strict adherence to official OWASP records."""

    def test_official_editions_dataset_completeness(self) -> None:
        """Must include all official published editions: 2003, 2004, 2007, 2010, 2013, 2017, 2021, 2025."""
        identifiers = [e["edition_identifier"] for e in OFFICIAL_EDITIONS_DATA]
        expected_editions = ["2003", "2004", "2007", "2010", "2013", "2017", "2021", "2025"]
        assert len(identifiers) == 8
        for exp in expected_editions:
            assert exp in identifiers

    def test_no_invented_editions(self) -> None:
        """Must not invent editions for years when OWASP did not publish a new Top 10."""
        identifiers = [e["edition_identifier"] for e in OFFICIAL_EDITIONS_DATA]
        invented_years = [
            "2005",
            "2006",
            "2008",
            "2009",
            "2011",
            "2012",
            "2014",
            "2015",
            "2016",
            "2018",
            "2019",
            "2020",
            "2022",
            "2023",
            "2024",
        ]
        for year in invented_years:
            assert year not in identifiers

    def test_every_edition_has_ten_categories(self) -> None:
        for ed in OFFICIAL_EDITIONS_DATA:
            cats = ed["categories"]
            assert len(cats) == 10
            for c in cats:
                assert c["category_code"]
                assert c["category_title"]
                assert c["category_description"]
                assert c["source_url"]


class TestTaxonomyIngestionService:
    """Tests for the ingestion service: idempotency, change detection, and audit runs."""

    def test_initial_ingestion(self, db_session: Session) -> None:
        run = TaxonomyIngestionService.run_ingestion(db_session)
        assert run.status == "CHANGES_DETECTED"
        assert run.editions_processed == 8
        assert run.categories_created == 80
        assert run.requires_admin_review is True

        # Verify database records
        editions = list(db_session.scalars(select(OWASPEdition)).all())
        assert len(editions) == 8
        categories = list(db_session.scalars(select(OWASPCategory)).all())
        assert len(categories) == 80

    def test_ingestion_idempotency(self, db_session: Session) -> None:
        # First run: initial population
        TaxonomyIngestionService.run_ingestion(db_session)

        # Second run: identical feed
        run2 = TaxonomyIngestionService.run_ingestion(db_session)
        assert run2.status == "NO_CHANGE"
        assert run2.categories_created == 0
        assert run2.categories_updated == 0
        assert run2.requires_admin_review is False

        # Verify no duplicate editions or categories
        editions = list(db_session.scalars(select(OWASPEdition)).all())
        assert len(editions) == 8
        categories = list(db_session.scalars(select(OWASPCategory)).all())
        assert len(categories) == 80

    def test_change_detection_and_review_flag(self, db_session: Session) -> None:
        # Initial run
        TaxonomyIngestionService.run_ingestion(db_session)

        # Create modified feed simulating an upstream definition update
        modified_feed = [dict(e) for e in OFFICIAL_EDITIONS_DATA]
        # Modify 2021 A01 description
        ed_2021 = next(e for e in modified_feed if e["edition_identifier"] == "2021")
        ed_2021["categories"] = [dict(c) for c in ed_2021["categories"]]
        ed_2021["categories"][0]["category_description"] = "UPDATED DESCRIPTION FROM UPSTREAM SOURCE"

        run_updated = TaxonomyIngestionService.run_ingestion(db_session, feed_data=modified_feed)
        assert run_updated.status == "CHANGES_DETECTED"
        assert run_updated.requires_admin_review is True
        assert run_updated.categories_updated >= 1

        # Check category was actually updated
        cat = db_session.scalars(select(OWASPCategory).where(OWASPCategory.category_code == "A01:2021")).first()
        assert cat is not None
        assert "UPDATED DESCRIPTION" in cat.category_description


class TestTaxonomyAPIEndpoints:
    """HTTP API integration tests for /api/v1/taxonomy endpoints."""

    def test_api_list_editions(self, client: TestClient) -> None:
        # Trigger initial ingestion
        client.post("/api/v1/taxonomy/ingest")

        res = client.get("/api/v1/taxonomy/editions")
        assert res.status_code == status.HTTP_200_OK
        editions = res.json()
        assert len(editions) == 8
        identifiers = [e["edition_identifier"] for e in editions]
        assert "2025" in identifiers
        assert "2021" in identifiers
        assert "2003" in identifiers

    def test_api_get_edition_by_identifier(self, client: TestClient) -> None:
        client.post("/api/v1/taxonomy/ingest")

        res = client.get("/api/v1/taxonomy/editions/2025")
        assert res.status_code == status.HTTP_200_OK
        data = res.json()
        assert data["edition_identifier"] == "2025"
        assert data["title"] == "OWASP Top 10: 2025"
        assert data["publication_year"] == 2025
        assert len(data["categories"]) == 10
        assert data["categories"][0]["category_code"] == "A01:2025"

    def test_api_get_lineage_timeline(self, client: TestClient) -> None:
        res = client.get("/api/v1/taxonomy/lineage")
        assert res.status_code == status.HTTP_200_OK
        lineage = res.json()
        assert len(lineage) >= 19
        theme_names = [item["theme"] for item in lineage]
        assert "Broken Access Control" in theme_names
        assert "Injection (incl. XSS)" in theme_names
        assert "Security Misconfiguration" in theme_names
        assert "SSRF" in theme_names
        assert "Exception / Error Handling" in theme_names

    def test_api_get_invalid_edition_returns_404(self, client: TestClient) -> None:
        res = client.get("/api/v1/taxonomy/editions/1999")
        assert res.status_code == status.HTTP_404_NOT_FOUND

    def test_api_ingestion_history(self, client: TestClient) -> None:
        # Trigger ingestion
        client.post("/api/v1/taxonomy/ingest")

        res = client.get("/api/v1/taxonomy/ingest/history")
        assert res.status_code == status.HTTP_200_OK
        history = res.json()
        assert len(history) > 0
        assert history[0]["status"] in ("CHANGES_DETECTED", "NO_CHANGE")

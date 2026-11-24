"""OWASP Sentinel - Scope Grants & Asset Inventory Tests (Phase 2)

Verifies scope boundaries, asset registration, port/protocol controls,
subdomain policies, approval workflows, and pre-scan clearance checks.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.exceptions import SentinelException, UnauthorizedTargetError
from app.models.schemas.asset import (
    AssetApprovalUpdateRequest,
    AssetRegisterRequest,
)
from app.models.schemas.scope import ScopeGrantCreate
from app.services import asset_service, scope_service


@pytest.fixture
def active_scope(db_session: Session):
    """Creates a standard active scope grant fixture."""
    now = datetime.now(timezone.utc)
    scope_code = f"TEST-SCOPE-{int(now.timestamp() * 1000)}"
    data = ScopeGrantCreate(
        organization_name="Acme Cyber Corp",
        scope_code=scope_code,
        title="Q4 2026 Web Assessment",
        authorized_by="sec-admin@acme.com",
        authorization_document_ref="AGREEMENT-2026-009",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
        max_requests_per_minute=120,
        request_budget=10000,
        allowed_protocols=["http", "https"],
        allowed_ports=[80, 443, 8080, 8443],
        allow_subdomains=False,  # Subdomains require explicit review
        allow_private_ips=False,
    )
    return scope_service.create_scope_grant(db_session, data)


class TestScopeGrantLifecycle:
    """Tests for ScopeGrant management and validity constraints."""

    def test_create_scope_grant_success(self, db_session: Session) -> None:
        now = datetime.now(timezone.utc)
        data = ScopeGrantCreate(
            organization_name="Global Defense Ltd",
            scope_code=f"SCOPE-DEF-{int(now.timestamp())}",
            title="External Security Audit",
            authorized_by="ciso@globaldefense.com",
            valid_from=now,
            valid_until=now + timedelta(days=7),
            allowed_ports=[443],
        )
        scope = scope_service.create_scope_grant(db_session, data)
        assert scope.id is not None
        assert scope.scope_code.startswith("SCOPE-DEF-")
        assert scope.is_active is True

    def test_duplicate_scope_code_rejected(self, db_session: Session, active_scope) -> None:
        now = datetime.now(timezone.utc)
        duplicate_data = ScopeGrantCreate(
            organization_name="Other Org",
            scope_code=active_scope.scope_code,  # Duplicate code
            title="Duplicate Title",
            authorized_by="admin@other.com",
            valid_from=now,
            valid_until=now + timedelta(days=5),
        )
        with pytest.raises(SentinelException) as exc_info:
            scope_service.create_scope_grant(db_session, duplicate_data)
        assert "already exists" in exc_info.value.message

    def test_expired_scope_check(self, db_session: Session) -> None:
        now = datetime.now(timezone.utc)
        data = ScopeGrantCreate(
            organization_name="Expired Org",
            scope_code=f"EXPIRED-{int(now.timestamp())}",
            title="Old Scope",
            authorized_by="admin@expired.com",
            valid_from=now - timedelta(days=10),
            valid_until=now - timedelta(days=1),  # Expired yesterday
        )
        scope = scope_service.create_scope_grant(db_session, data)
        is_valid, reason = scope_service.is_scope_valid(scope)
        assert is_valid is False
        assert "expired" in reason.lower()


class TestAuthorizedAssetRegistration:
    """Tests for registering target assets into approved inventory."""

    def test_register_asset_success(self, db_session: Session, active_scope) -> None:
        req = AssetRegisterRequest(
            target="https://acme.com:8443/login",
            scope_code=active_scope.scope_code,
            is_authorized=True,
            asset_type="URL",
            skip_dns_resolution=True,
        )
        asset = asset_service.register_asset(db_session, req)
        assert asset.id is not None
        assert asset.host == "acme.com"
        assert asset.port == 8443
        assert asset.approval_status == "APPROVED"
        assert asset.canonical_url == "https://acme.com:8443/login"

    def test_disallowed_port_rejected(self, db_session: Session, active_scope) -> None:
        # Port 9999 is not in active_scope's allowed_ports ([80, 443, 8080, 8443])
        req = AssetRegisterRequest(
            target="https://acme.com:9999/admin",
            scope_code=active_scope.scope_code,
            is_authorized=True,
            skip_dns_resolution=True,
        )
        with pytest.raises(SentinelException) as exc_info:
            asset_service.register_asset(db_session, req)
        assert exc_info.value.code == "DISALLOWED_PORT"

    def test_subdomain_requires_pending_approval_when_not_in_scope(self, db_session: Session, active_scope) -> None:
        # active_scope has allow_subdomains = False
        req = AssetRegisterRequest(
            target="https://dev-portal.acme.com/api",
            scope_code=active_scope.scope_code,
            is_authorized=True,
            asset_type="SUBDOMAIN",
            skip_dns_resolution=True,
        )
        asset = asset_service.register_asset(db_session, req)
        # Discovered subdomains must not automatically become approved scan targets
        assert asset.approval_status == "PENDING"
        assert asset.approved_by is None

    def test_register_without_authorization_rejected(self, db_session: Session, active_scope) -> None:
        req = AssetRegisterRequest(
            target="https://acme.com",
            scope_code=active_scope.scope_code,
            is_authorized=False,  # Unauthorized!
            skip_dns_resolution=True,
        )
        with pytest.raises(UnauthorizedTargetError):
            asset_service.register_asset(db_session, req)


class TestTargetPreScanClearance:
    """Tests for pre-scan target authorization clearance (check_target_authorization)."""

    def test_cleared_target(self, db_session: Session, active_scope) -> None:
        # Register and approve asset
        req = AssetRegisterRequest(
            target="https://acme.com/secure-portal",
            scope_code=active_scope.scope_code,
            is_authorized=True,
            skip_dns_resolution=True,
        )
        asset = asset_service.register_asset(db_session, req)

        # Pre-scan clearance check
        res = asset_service.check_target_authorization(db_session, "https://acme.com/secure-portal")
        assert res.is_authorized is True
        assert res.status == "AUTHORIZED"
        assert res.asset_id == asset.id
        assert res.rate_limit_per_minute == 120
        assert res.request_budget == 10000

    def test_unregistered_target_denied(self, db_session: Session) -> None:
        res = asset_service.check_target_authorization(db_session, "https://unregistered-domain.com")
        assert res.is_authorized is False
        assert res.status == "UNAUTHORIZED_TARGET"

    def test_pending_subdomain_denied_until_approved(self, db_session: Session, active_scope) -> None:
        req = AssetRegisterRequest(
            target="https://test.acme.com",
            scope_code=active_scope.scope_code,
            is_authorized=True,
            asset_type="SUBDOMAIN",
            skip_dns_resolution=True,
        )
        asset = asset_service.register_asset(db_session, req)
        assert asset.approval_status == "PENDING"

        # Pre-scan check must deny pending target
        pre_check = asset_service.check_target_authorization(db_session, "https://test.acme.com")
        assert pre_check.is_authorized is False
        assert pre_check.status == "APPROVAL_PENDING_OR_REVOKED"

        # Admin approves asset
        asset_service.update_asset_approval(
            db_session,
            asset.id,
            AssetApprovalUpdateRequest(
                approval_status="APPROVED",
                approved_by="admin@acme.com",
                reason="Verified ownership",
            ),
        )

        # Pre-scan check must now allow it
        post_check = asset_service.check_target_authorization(db_session, "https://test.acme.com")
        assert post_check.is_authorized is True
        assert post_check.status == "AUTHORIZED"


class TestAssetAndScopeAPIEndpoints:
    """HTTP API integration tests for Phase 2 endpoints."""

    def test_api_scope_and_asset_workflow(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        scope_code = f"API-SCOPE-{int(now.timestamp())}"

        # 1. Create Scope Grant via API
        scope_payload = {
            "organization_name": "API Test Org",
            "scope_code": scope_code,
            "title": "API Scope Test",
            "authorized_by": "api-lead@test.com",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=14)).isoformat(),
            "max_requests_per_minute": 90,
            "request_budget": 5000,
            "allowed_protocols": ["http", "https"],
            "allowed_ports": [80, 443],
            "allow_subdomains": True,
            "allow_private_ips": False,
        }
        res_scope = client.post("/api/v1/scopes", json=scope_payload)
        assert res_scope.status_code == status.HTTP_201_CREATED
        scope_data = res_scope.json()
        assert scope_data["scope_code"] == scope_code

        # 2. Register Target Asset via API
        asset_payload = {
            "target": "https://api-test.example.com",
            "scope_code": scope_code,
            "is_authorized": True,
            "asset_type": "DOMAIN",
            "skip_dns_resolution": True,
        }
        res_asset = client.post("/api/v1/assets", json=asset_payload)
        assert res_asset.status_code == status.HTTP_201_CREATED
        asset_data = res_asset.json()
        assert asset_data["canonical_url"] == "https://api-test.example.com/"
        assert asset_data["approval_status"] == "APPROVED"

        # 3. Check Pre-Scan Authorization via API
        check_payload = {
            "target": "https://api-test.example.com",
            "scope_code": scope_code,
        }
        res_check = client.post("/api/v1/assets/check-authorization", json=check_payload)
        assert res_check.status_code == status.HTTP_200_OK
        check_data = res_check.json()
        assert check_data["is_authorized"] is True
        assert check_data["status"] == "AUTHORIZED"
        assert check_data["rate_limit_per_minute"] == 90

        # 4. Verify Audit Event logged
        res_audit = client.get("/api/v1/audit")
        assert res_audit.status_code == status.HTTP_200_OK
        audit_events = res_audit.json()
        assert len(audit_events) > 0
        event_types = [e["event_type"] for e in audit_events]
        assert "SCOPE_CREATED" in event_types
        assert "TARGET_REGISTERED" in event_types

        # 5. Delete Asset via API
        res_del = client.delete(f"/api/v1/assets/{asset_data['id']}")
        assert res_del.status_code == status.HTTP_200_OK
        assert res_del.json()["status"] == "success"

        # Verify asset no longer listed
        res_list = client.get("/api/v1/assets")
        assert res_list.status_code == status.HTTP_200_OK
        remaining_ids = [a["id"] for a in res_list.json()]
        assert asset_data["id"] not in remaining_ids

    def test_api_bulk_delete_assets_by_domain(self, client: TestClient) -> None:
        now = datetime.now(timezone.utc)
        scope_code = f"BULK-DEL-{int(now.timestamp())}"
        client.post("/api/v1/scopes", json={
            "organization_name": "Bulk Org",
            "scope_code": scope_code,
            "title": "Bulk Scope",
            "authorized_by": "bulk@test.com",
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=7)).isoformat(),
            "allowed_protocols": ["https"],
            "allowed_ports": [443],
            "allow_subdomains": True,
        })
        # Register two assets for domain test-bulk.com
        client.post("/api/v1/assets", json={
            "target": "https://sub1.test-bulk.com",
            "scope_code": scope_code,
            "is_authorized": True,
            "asset_type": "SUBDOMAIN",
            "skip_dns_resolution": True,
        })
        client.post("/api/v1/assets", json={
            "target": "https://sub2.test-bulk.com",
            "scope_code": scope_code,
            "is_authorized": True,
            "asset_type": "SUBDOMAIN",
            "skip_dns_resolution": True,
        })
        # Delete by domain
        res_bulk = client.delete("/api/v1/assets/bulk/by-domain?domain=test-bulk.com")
        assert res_bulk.status_code == status.HTTP_200_OK
        data = res_bulk.json()
        assert data["status"] == "success"
        assert data["deleted_count"] >= 2


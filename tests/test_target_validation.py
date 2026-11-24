"""OWASP Sentinel - Target Input Validation and Security Policy Tests

Tests all input parsing, normalization, scheme restrictions, port bounds,
explicit authorization enforcement, and SSRF boundary safeguards.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.core.exceptions import (
    SecurityRestrictionError,
    TargetValidationError,
    UnauthorizedTargetError,
)
from app.core.validator import TargetValidator
from app.models.schemas.target import TargetValidationRequest


class TestTargetValidatorLogic:
    """Direct unit tests for TargetValidator business logic and SSRF defenses."""

    def test_valid_https_url(self) -> None:
        req = TargetValidationRequest(
            target="https://example.com/api/v1?query=test#section",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.is_valid is True
        assert res.scheme == "https"
        assert res.host == "example.com"
        assert res.port == 443
        assert res.path == "/api/v1?query=test"
        # URL fragment must be stripped
        assert "#section" not in res.canonical_url
        assert res.canonical_url == "https://example.com/api/v1?query=test"

    def test_default_scheme_applied_when_missing(self) -> None:
        req = TargetValidationRequest(
            target="example.com",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.scheme == "https"
        assert res.host == "example.com"
        assert res.port == 443
        assert res.canonical_url == "https://example.com/"

    def test_custom_port_preserved(self) -> None:
        req = TargetValidationRequest(
            target="https://example.com:8443/login",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.port == 8443
        assert res.canonical_url == "https://example.com:8443/login"

    def test_rejection_when_unauthorized(self) -> None:
        req = TargetValidationRequest(
            target="https://example.com",
            is_authorized=False,  # Un-authorized!
            skip_dns_resolution=True,
        )
        with pytest.raises(UnauthorizedTargetError) as exc_info:
            TargetValidator.validate(req)
        assert "Explicit authorization is required" in exc_info.value.message

    def test_rejection_of_unsupported_schemes(self) -> None:
        dangerous_targets = [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "gopher://example.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        for target in dangerous_targets:
            req = TargetValidationRequest(
                target=target,
                is_authorized=True,
                skip_dns_resolution=True,
            )
            with pytest.raises(TargetValidationError) as exc_info:
                TargetValidator.validate(req)
            assert "Unsupported protocol scheme" in exc_info.value.message

    def test_rejection_of_invalid_tcp_ports(self) -> None:
        invalid_ports = [0, 65536, 99999]
        for port in invalid_ports:
            req = TargetValidationRequest(
                target=f"https://example.com:{port}",
                is_authorized=True,
                skip_dns_resolution=True,
            )
            with pytest.raises(TargetValidationError) as exc_info:
                TargetValidator.validate(req)
            assert "outside valid TCP port range" in exc_info.value.message

    def test_ssrf_rejection_of_loopback_ip(self) -> None:
        loopbacks = ["http://127.0.0.1:8080", "https://127.0.0.2", "http://[::1]"]
        for loopback in loopbacks:
            req = TargetValidationRequest(
                target=loopback,
                is_authorized=True,
                skip_dns_resolution=True,
            )
            with pytest.raises(SecurityRestrictionError) as exc_info:
                TargetValidator.validate(req)
            assert "loopback address" in exc_info.value.message

    def test_ssrf_rejection_of_localhost_domain(self) -> None:
        req = TargetValidationRequest(
            target="http://localhost:8000",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        with pytest.raises(SecurityRestrictionError) as exc_info:
            TargetValidator.validate(req)
        assert "localhost" in exc_info.value.message

    def test_ssrf_rejection_of_cloud_metadata_ip(self) -> None:
        req = TargetValidationRequest(
            target="http://169.254.169.254/latest/meta-data/",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        with pytest.raises(SecurityRestrictionError) as exc_info:
            TargetValidator.validate(req)
        assert "protected cloud metadata" in exc_info.value.message

    def test_ssrf_rejection_of_cloud_metadata_hostname(self) -> None:
        req = TargetValidationRequest(
            target="http://metadata.google.internal/computeMetadata/v1/",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        with pytest.raises(SecurityRestrictionError) as exc_info:
            TargetValidator.validate(req)
        assert "restricted cloud metadata service" in exc_info.value.message

    def test_private_ip_blocked_by_default(self) -> None:
        private_ips = ["http://192.168.1.1:80", "http://10.0.0.1", "http://172.16.5.10"]
        for priv_ip in private_ips:
            req = TargetValidationRequest(
                target=priv_ip,
                is_authorized=True,
                allow_private_ips=False,  # Blocked by default
                skip_dns_resolution=True,
            )
            with pytest.raises(SecurityRestrictionError) as exc_info:
                TargetValidator.validate(req)
            assert "internal/private network address" in exc_info.value.message

    def test_private_ip_allowed_with_explicit_lab_override(self) -> None:
        req = TargetValidationRequest(
            target="http://192.168.1.50:8080/portal",
            is_authorized=True,
            allow_private_ips=True,  # Explicit lab override
            scope_grant_id="LAB-PENTEST-2026",
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.is_valid is True
        assert res.is_private_ip is True
        assert res.host == "192.168.1.50"
        assert res.port == 8080
        assert any("private network space" in warning for warning in res.security_warnings)

    def test_public_ip_target(self) -> None:
        # 93.184.216.34 is a routable public IP (example.com)
        req = TargetValidationRequest(
            target="https://93.184.216.34:443",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.is_valid is True
        assert res.is_ip_address is True
        assert res.is_private_ip is False
        assert res.host == "93.184.216.34"
        assert res.canonical_url == "https://93.184.216.34/"

    def test_rejection_of_control_characters(self) -> None:
        req = TargetValidationRequest(
            target="https://example.com/page\r\nInjected-Header: value",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        with pytest.raises(TargetValidationError) as exc_info:
            TargetValidator.validate(req)
        assert "illegal control" in exc_info.value.message

    def test_valid_ipv6_target_with_port(self) -> None:
        # 2001:db8::1 is RFC 3849 documentation prefix
        req = TargetValidationRequest(
            target="https://[2001:db8::1]:8443/status",
            is_authorized=True,
            allow_private_ips=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.is_valid is True
        assert res.is_ip_address is True
        assert res.port == 8443
        assert res.canonical_url == "https://[2001:db8::1]:8443/status"

    def test_trailing_dot_domain_normalization(self) -> None:
        req = TargetValidationRequest(
            target="https://example.com./test",
            is_authorized=True,
            skip_dns_resolution=True,
        )
        res = TargetValidator.validate(req)
        assert res.is_valid is True
        assert res.host == "example.com."
        assert res.canonical_url == "https://example.com./test"


class TestTargetValidationAPIEndpoints:
    """Integration tests for POST /api/v1/targets/validate."""

    def test_api_valid_target(self, client: TestClient, valid_scope_id: str) -> None:
        payload = {
            "target": "https://example.com:8443/app",
            "is_authorized": True,
            "scope_grant_id": valid_scope_id,
            "skip_dns_resolution": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_valid"] is True
        assert data["scheme"] == "https"
        assert data["host"] == "example.com"
        assert data["port"] == 8443
        assert data["canonical_url"] == "https://example.com:8443/app"
        assert data["scope_grant_id"] == valid_scope_id

    def test_api_unauthorized_rejection(self, client: TestClient) -> None:
        payload = {
            "target": "https://example.com",
            "is_authorized": False,  # Missing authorization
            "skip_dns_resolution": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["detail"]["code"] == "UNAUTHORIZED_TARGET"

    def test_api_disallowed_scheme(self, client: TestClient) -> None:
        payload = {
            "target": "ftp://files.example.com",
            "is_authorized": True,
            "skip_dns_resolution": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["detail"]["code"] == "TARGET_VALIDATION_ERROR"

    def test_api_loopback_ssrf_blocked(self, client: TestClient) -> None:
        payload = {
            "target": "http://127.0.0.1:8000",
            "is_authorized": True,
            "skip_dns_resolution": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["detail"]["code"] == "SECURITY_RESTRICTION_VIOLATION"

    def test_api_cloud_metadata_blocked(self, client: TestClient) -> None:
        payload = {
            "target": "http://169.254.169.254",
            "is_authorized": True,
            "skip_dns_resolution": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["detail"]["code"] == "SECURITY_RESTRICTION_VIOLATION"

    def test_api_empty_target_schema_validation(self, client: TestClient) -> None:
        payload = {
            "target": "   ",
            "is_authorized": True,
        }
        response = client.post("/api/v1/targets/validate", json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

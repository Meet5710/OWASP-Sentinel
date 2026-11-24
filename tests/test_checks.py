"""Tests for checks.py module validating OWASP Top 10 check functions."""

import inspect
from owasp_registry import CHECK_REGISTRY
import checks


def test_all_check_registry_functions_exist_in_checks() -> None:
    """Verify every check name declared in CHECK_REGISTRY is implemented in checks.py."""
    for cat_id, func_name in CHECK_REGISTRY.items():
        assert hasattr(checks, func_name), f"checks.py is missing function {func_name} for {cat_id}"
        func = getattr(checks, func_name)
        assert callable(func), f"{func_name} must be callable"

        # Check signature: (target_url, auth)
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        assert params == ["target_url", "auth"], f"{func_name} signature must be (target_url, auth)"


def test_non_automatable_categories_return_manual_review() -> None:
    """A03, A06, and A09 must return the exact required manual review dictionary."""
    expected_manual_a03 = [
        {
            "owasp_id": "A03",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]
    expected_manual_a06 = [
        {
            "owasp_id": "A06",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]
    expected_manual_a09 = [
        {
            "owasp_id": "A09",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]

    assert checks.run_supply_chain_checks("https://example.com", {}) == expected_manual_a03
    assert checks.run_design_checks("https://example.com", {}) == expected_manual_a06
    assert checks.run_logging_checks("https://example.com", {}) == expected_manual_a09


def test_crypto_checks_detects_http_plaintext() -> None:
    """A04 should flag plaintext HTTP protocol."""
    findings = checks.run_crypto_checks("http://insecure-target.local", {})
    assert len(findings) >= 1
    f = findings[0]
    assert f["owasp_id"] == "A04"
    assert f["severity"] == "high"
    assert "Cleartext HTTP Protocol Detected" in f["title"]
    assert f["source"] == "scanner"


def test_graceful_handling_on_unreachable_target() -> None:
    """All automated check functions must return a list gracefully on unreachable targets without crashing."""
    unreachable_url = "http://127.0.0.1:54321/offline_test"
    dummy_auth = {"token": "dummy"}

    for cat_id, func_name in CHECK_REGISTRY.items():
        func = getattr(checks, func_name)
        findings = func(unreachable_url, dummy_auth)
        assert isinstance(findings, list), f"{func_name} must return a list"
        for item in findings:
            assert "owasp_id" in item
            assert "title" in item
            assert "severity" in item
            assert "evidence" in item
            assert "source" in item
            assert item["source"] in ("scanner", "manual")
            assert item["severity"] in ("high", "medium", "low", "info")


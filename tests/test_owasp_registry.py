"""Tests for owasp_registry module."""

from owasp_registry import OWASP_CATEGORIES, CHECK_REGISTRY, build_scan_command


def test_owasp_categories_mapping() -> None:
    expected = {
        "A01": "Broken Access Control",
        "A02": "Security Misconfiguration",
        "A03": "Software Supply Chain Failures",
        "A04": "Cryptographic Failures",
        "A05": "Injection",
        "A06": "Insecure Design",
        "A07": "Authentication Failures",
        "A08": "Software or Data Integrity Failures",
        "A09": "Security Logging and Alerting Failures",
        "A10": "Mishandling of Exceptional Conditions",
    }
    assert OWASP_CATEGORIES == expected
    assert len(OWASP_CATEGORIES) == 10


def test_check_registry_mapping() -> None:
    expected = {
        "A01": "run_access_control_checks",
        "A02": "run_misconfig_checks",
        "A03": "run_supply_chain_checks",
        "A04": "run_crypto_checks",
        "A05": "run_injection_checks",
        "A06": "run_design_checks",
        "A07": "run_auth_checks",
        "A08": "run_integrity_checks",
        "A09": "run_logging_checks",
        "A10": "run_exception_checks",
    }
    assert CHECK_REGISTRY == expected
    assert len(CHECK_REGISTRY) == 10
    # Every category must have a mapped check
    for cat_id in OWASP_CATEGORIES:
        assert cat_id in CHECK_REGISTRY


def test_build_scan_command() -> None:
    cmd = build_scan_command("https://example.com", ["A01", "A02", "A05"])
    assert cmd == "python -m scanner.main scan --target https://example.com --checks A01,A02,A05"

    cmd_single = build_scan_command("http://127.0.0.1:8000", ["A01"])
    assert cmd_single == "python -m scanner.main scan --target http://127.0.0.1:8000 --checks A01"

    cmd_all = build_scan_command("https://target.local", list(OWASP_CATEGORIES.keys()))
    assert cmd_all == (
        "python -m scanner.main scan --target https://target.local "
        "--checks A01,A02,A03,A04,A05,A06,A07,A08,A09,A10"
    )


"""Unit tests for scanner_main.py orchestrator module."""

from unittest.mock import patch, MagicMock
import scanner_main


def test_scan_with_all_ids() -> None:
    """Verify scan handles all 10 OWASP IDs and constructs valid summary."""
    all_ids = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]

    with patch("scan_http.check_access_control", return_value=[{"owasp_id": "A01", "title": "A01 finding"}]), \
         patch("scan_http.check_security_headers", return_value=[{"owasp_id": "A02", "title": "A02 finding"}]), \
         patch("scan_http.check_reflected_parameters", return_value=[{"owasp_id": "A05", "title": "A05 finding"}]), \
         patch("scan_http.check_cookie_flags", return_value=[{"owasp_id": "A07", "title": "A07 finding"}]):

        results = scanner_main.scan(
            target_url="https://example.com",
            selected_ids=all_ids,
            auth={},
            tools={},
        )

    assert results["target"] == "https://example.com"
    findings = results["findings"]
    summary = results["summary"]

    assert summary["total"] == len(findings)
    assert set(summary["by_owasp"].keys()) == set(all_ids)

    # A03, A06, A09, A10 should have manual review findings
    manual_reviews = [f for f in findings if f.get("source") == "manual"]
    manual_ids = {f["owasp_id"] for f in manual_reviews}
    assert {"A03", "A06", "A09", "A10"}.issubset(manual_ids)


def test_scan_a05_with_sqlmap_path() -> None:
    """When sqlmap_path is provided for A05, run_sqlmap_cli is executed and parsed."""
    sqlmap_output = """
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
    ---
    [INFO] the back-end DBMS is MySQL
    sqlmap identified the following injection points with a total of 56 HTTP(s) requests:
    ---
    Parameter: id (GET)
        Type: boolean-based blind
    ---
    [INFO] GET parameter 'id' is vulnerable
    """

    mock_sqlmap_res = {
        "stdout": sqlmap_output,
        "stderr": "",
        "exit_code": 0,
    }

    with patch("scan_http.check_reflected_parameters", return_value=[]), \
         patch("scanner_main.run_sqlmap_cli", return_value=mock_sqlmap_res) as mock_sqlmap:

        results = scanner_main.scan(
            target_url="http://example.com/item?id=1",
            selected_ids=["A05"],
            auth={},
            tools={"sqlmap_path": "vendor/sqlmap/sqlmap.py"},
        )

    mock_sqlmap.assert_called_once_with("http://example.com/item?id=1", sqlmap_path="vendor/sqlmap/sqlmap.py")
    a05_findings = [f for f in results["findings"] if f["owasp_id"] == "A05"]
    assert len(a05_findings) >= 1
    assert any("id" in f["title"] for f in a05_findings)
    assert results["summary"]["by_owasp"]["A05"] == len(a05_findings)


def test_scan_a03_with_requirements_path() -> None:
    """When requirements_path is provided for A03, run_pip_audit is executed and parsed."""
    mock_audit_res = {
        "vulnerabilities": [
            {
                "id": "CVE-2023-32681",
                "package": "requests",
                "version": "2.28.1",
                "fix_versions": ["2.31.0"],
                "description": "Unintended leak of Proxy-Authorization header.",
            },
            {
                "id": "CVE-2022-40897",
                "package": "setuptools",
                "version": "65.5.0",
                "fix_versions": ["65.5.1"],
                "description": "Regular Expression Denial of Service (ReDoS).",
            },
        ]
    }

    with patch("scanner_main.run_pip_audit", return_value=mock_audit_res) as mock_pip_audit:
        results = scanner_main.scan(
            target_url="https://example.com",
            selected_ids=["A03"],
            auth={},
            tools={"requirements_path": "requirements.txt"},
        )

    mock_pip_audit.assert_called_once_with("requirements.txt")
    a03_findings = [f for f in results["findings"] if f["owasp_id"] == "A03"]
    assert len(a03_findings) == 2
    assert results["summary"]["by_owasp"]["A03"] == 2
    cves = {f.get("cve") for f in a03_findings}
    assert "CVE-2023-32681" in cves
    assert "CVE-2022-40897" in cves


def test_scan_manual_stubs_a06_a09_a10() -> None:
    """Verify A06, A09, A10 return manual review findings."""
    results = scanner_main.scan(
        target_url="https://example.com",
        selected_ids=["A06", "A09", "A10"],
        auth={},
        tools={},
    )

    findings = results["findings"]
    assert len(findings) == 3
    for f in findings:
        assert f["source"] == "manual"
        assert f["title"] == "Manual review required"
        assert f["severity"] == "info"
        assert f["owasp_id"] in ["A06", "A09", "A10"]

    assert results["summary"]["total"] == 3
    assert results["summary"]["by_owasp"]["A06"] == 1
    assert results["summary"]["by_owasp"]["A09"] == 1
    assert results["summary"]["by_owasp"]["A10"] == 1


def test_scan_summary_structure() -> None:
    """Verify summary format and empty findings behavior."""
    with patch("scan_http.check_security_headers", return_value=[]):
        results = scanner_main.scan(
            target_url="https://secure.example.com",
            selected_ids=["A02"],
            auth={},
            tools={},
        )

    assert results["target"] == "https://secure.example.com"
    assert results["findings"] == []
    assert results["summary"] == {
        "total": 0,
        "by_owasp": {"A02": 0},
    }


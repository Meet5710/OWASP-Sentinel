"""Unit tests for main.py CLI driver."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import pytest

import main


@pytest.fixture
def temp_auth_file(tmp_path: Path):
    """Factory fixture for generating test authorization JSON files."""
    def _create(approved_by="Security Team Lead", expiry=None):
        if expiry is None:
            expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        auth_file = tmp_path / "auth.json"
        data = {"approved_by": approved_by, "expiry": expiry, "token": "secret_token_123"}
        auth_file.write_text(json.dumps(data), encoding="utf-8")
        return str(auth_file)
    return _create


def test_load_and_validate_auth_valid(temp_auth_file) -> None:
    """Valid auth file with future expiry date is loaded successfully."""
    future_time = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    path = temp_auth_file(approved_by="Alice Auditor", expiry=future_time)

    data = main.load_and_validate_auth(path)
    assert data["approved_by"] == "Alice Auditor"
    assert data["token"] == "secret_token_123"


def test_load_and_validate_auth_numeric_timestamp(temp_auth_file) -> None:
    """Numeric epoch timestamp in the future is validated."""
    future_timestamp = (datetime.now(timezone.utc) + timedelta(days=7)).timestamp()
    path = temp_auth_file(approved_by="Bob Admin", expiry=future_timestamp)

    data = main.load_and_validate_auth(path)
    assert data["approved_by"] == "Bob Admin"


def test_load_and_validate_auth_expired(temp_auth_file) -> None:
    """Expired auth file raises ValueError with expiry notice."""
    past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    path = temp_auth_file(approved_by="Carol Security", expiry=past_time)

    with pytest.raises(ValueError, match="Authorization expired"):
        main.load_and_validate_auth(path)


def test_load_and_validate_auth_missing_fields(tmp_path: Path) -> None:
    """Missing approved_by or expiry raises ValueError."""
    file1 = tmp_path / "no_approved_by.json"
    file1.write_text(json.dumps({"expiry": "2030-01-01T00:00:00Z"}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field: 'approved_by'"):
        main.load_and_validate_auth(file1)

    file2 = tmp_path / "no_expiry.json"
    file2.write_text(json.dumps({"approved_by": "Ops"}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field: 'expiry'"):
        main.load_and_validate_auth(file2)


def test_load_and_validate_auth_nonexistent_file() -> None:
    """Non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        main.load_and_validate_auth("non_existent_file_xyz_123.json")


def test_scan_subcommand_full_flow(tmp_path: Path, temp_auth_file) -> None:
    """Verify scan CLI runs end-to-end: auth check, scan invocation, JSON report, summary table."""
    auth_file = temp_auth_file(approved_by="Auditor General")
    report_file = tmp_path / "custom_report.json"

    mock_scan_result = {
        "target": "https://example.com",
        "findings": [
            {
                "owasp_id": "A02",
                "title": "Missing CSP Header",
                "severity": "medium",
                "evidence": "CSP header missing",
                "source": "scanner",
            },
            {
                "owasp_id": "A06",
                "title": "Manual review required",
                "severity": "info",
                "evidence": "Requires source code review",
                "source": "manual",
            },
        ],
        "summary": {
            "total": 2,
            "by_owasp": {"A01": 0, "A02": 1, "A06": 1},
        },
    }

    cli_args = [
        "scan",
        "--target", "https://example.com",
        "--checks", "A01,A02,A06",
        "--auth-file", auth_file,
        "--sqlmap-path", "vendor/sqlmap/sqlmap.py",
        "--xsstrike-path", "vendor/xsstrike/xsstrike.py",
        "--requirements-path", "requirements.txt",
        "--output", str(report_file),
    ]

    with patch("main.scan", return_value=mock_scan_result) as mock_scan:
        ret = main.main(cli_args)

    assert ret == 0
    mock_scan.assert_called_once()
    call_kwargs = mock_scan.call_args.kwargs
    assert call_kwargs["target_url"] == "https://example.com"
    assert call_kwargs["selected_ids"] == ["A01", "A02", "A06"]
    assert call_kwargs["auth"]["approved_by"] == "Auditor General"
    assert call_kwargs["tools"]["sqlmap_path"] == "vendor/sqlmap/sqlmap.py"
    assert call_kwargs["tools"]["xsstrike_path"] == "vendor/xsstrike/xsstrike.py"
    assert call_kwargs["tools"]["requirements_path"] == "requirements.txt"

    # Verify JSON output was written
    assert report_file.is_file()
    saved_data = json.loads(report_file.read_text(encoding="utf-8"))
    assert saved_data["target"] == "https://example.com"
    assert saved_data["summary"]["total"] == 2


def test_scan_subcommand_expired_auth_aborts(temp_auth_file, capsys) -> None:
    """When auth file is expired, scan subcommand aborts with non-zero exit code."""
    past_time = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    auth_file = temp_auth_file(approved_by="Auditor", expiry=past_time)

    cli_args = [
        "scan",
        "--target", "https://example.com",
        "--auth-file", auth_file,
    ]

    ret = main.main(cli_args)
    assert ret == 1
    captured = capsys.readouterr()
    assert "Authorization expired" in captured.err


def test_format_summary_table_columns() -> None:
    """Summary table contains OWASP ID, Category, Findings Count, and Status."""
    mock_results = {
        "findings": [
            {"owasp_id": "A02", "source": "scanner"},
            {"owasp_id": "A06", "source": "manual"},
        ],
        "summary": {
            "total": 2,
            "by_owasp": {"A01": 0, "A02": 1, "A06": 1},
        },
    }

    table = main.format_summary_table(
        selected_ids=["A01", "A02", "A06"],
        results=mock_results,
        tools={},
    )

    assert "OWASP ID" in table
    assert "Category" in table
    assert "Findings Count" in table
    assert "Status" in table
    assert "A01" in table
    assert "Broken Access Control" in table
    assert "A02" in table
    assert "Security Misconfiguration" in table
    assert "A06" in table
    assert "Insecure Design" in table
    assert "scanned" in table
    assert "manual" in table


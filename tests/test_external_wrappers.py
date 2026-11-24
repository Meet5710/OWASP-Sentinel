"""Unit tests for external_wrappers.py module."""

from unittest.mock import patch, MagicMock
import external_wrappers


def test_run_sqlmap_cli() -> None:
    """Verify sqlmap CLI subprocess invocation flags and return structure."""
    mock_proc = MagicMock()
    mock_proc.stdout = "[*] starting at 12:00:00\n[INFO] testing connection..."
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = external_wrappers.run_sqlmap_cli("http://test.local/api", "/opt/sqlmap/sqlmap.py")

    expected_cmd = [
        "python3",
        "/opt/sqlmap/sqlmap.py",
        "-u",
        "http://test.local/api",
        "--batch",
        "--level=1",
        "--risk=1",
        "--output-dir",
        "/tmp/sqlmap_out",
    ]
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == expected_cmd
    assert kwargs.get("capture_output") is True
    assert kwargs.get("shell") is not True

    assert result["stdout"] == mock_proc.stdout
    assert result["stderr"] == ""
    assert result["exit_code"] == 0


def test_run_xsstrike_cli_vulnerable() -> None:
    """Verify XSStrike CLI subprocess invocation and vulnerable detection."""
    mock_proc = MagicMock()
    mock_proc.stdout = "[+] Vulnerable parameter: q\n[+] Vector: <svg/onload=alert(1)>"
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = external_wrappers.run_xsstrike_cli("http://test.local/search?q=test", "/opt/xsstrike/xsstrike.py")

    expected_cmd = [
        "python3",
        "/opt/xsstrike/xsstrike.py",
        "-u",
        "http://test.local/search?q=test",
        "--skip",
        "--skip-dom",
        "--console-log-level",
        "VULN",
    ]
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == expected_cmd
    assert kwargs.get("capture_output") is True
    assert kwargs.get("shell") is not True

    assert result["stdout"] == mock_proc.stdout
    assert result["stderr"] == ""
    assert result["exit_code"] == 0
    assert result["vulnerable"] is True


def test_run_xsstrike_cli_not_vulnerable() -> None:
    """Verify XSStrike returns vulnerable=False when Vulnerable marker is absent."""
    mock_proc = MagicMock()
    mock_proc.stdout = "[-] Target appears safe"
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        result = external_wrappers.run_xsstrike_cli("http://test.local/search?q=test", "/opt/xsstrike/xsstrike.py")

    assert result["vulnerable"] is False


def test_run_pip_audit_json_parsing() -> None:
    """Verify pip-audit subprocess invocation and JSON parsing into vulnerabilities list."""
    mock_proc = MagicMock()
    mock_proc.stdout = (
        '{"dependencies": [{"name": "urllib3", "version": "1.26.4", '
        '"vulns": [{"id": "PYSEC-2021-108", "fix_versions": ["1.26.5"], "description": "ReDoS"}]}]}'
    )
    mock_proc.stderr = ""
    mock_proc.returncode = 1

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        result = external_wrappers.run_pip_audit("requirements.txt")

    expected_cmd = [
        "pip-audit",
        "-r",
        "requirements.txt",
        "--format",
        "json",
    ]
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == expected_cmd
    assert kwargs.get("capture_output") is True
    assert kwargs.get("shell") is not True

    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["id"] == "PYSEC-2021-108"
    assert vuln["package"] == "urllib3"


def test_run_pip_audit_direct_vulnerabilities_format() -> None:
    """Verify pip-audit handles mock with direct vulnerabilities list."""
    mock_proc = MagicMock()
    mock_proc.stdout = '{"vulnerabilities": [{"id": "CVE-2023-9999", "package": "flask"}]}'
    mock_proc.returncode = 0

    with patch("subprocess.run", return_value=mock_proc):
        result = external_wrappers.run_pip_audit("requirements.txt")

    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["id"] == "CVE-2023-9999"


def test_run_pip_audit_invalid_json() -> None:
    """Verify pip-audit handles empty or invalid JSON output gracefully."""
    mock_proc = MagicMock()
    mock_proc.stdout = "Not JSON output error"
    mock_proc.returncode = 1

    with patch("subprocess.run", return_value=mock_proc):
        result = external_wrappers.run_pip_audit("requirements.txt")

    assert result == {"vulnerabilities": []}


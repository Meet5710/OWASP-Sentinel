"""Tests for xssspect.external_runner — XSStrike subprocess wrapper.

All tests mock subprocess.run to avoid invoking XSStrike for real.
"""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from xssspect.external_runner import run_xsstrike, _strip_ansi, _SUCCESS_MARKERS


# ---------------------------------------------------------------------------
# _strip_ansi helper
# ---------------------------------------------------------------------------

class TestStripAnsi:
    def test_removes_color_codes(self) -> None:
        raw = "\x1b[92m[+]\x1b[0m Payload: <script>alert(1)</script>"
        assert _strip_ansi(raw) == "[+] Payload: <script>alert(1)</script>"

    def test_plain_text_unchanged(self) -> None:
        plain = "No colors here"
        assert _strip_ansi(plain) == plain


# ---------------------------------------------------------------------------
# run_xsstrike — successful invocation
# ---------------------------------------------------------------------------

class TestRunXSStrikeSuccess:
    @patch("xssspect.external_runner.subprocess.run")
    def test_vulnerable_detected(self, mock_run: MagicMock) -> None:
        """When XSStrike prints 'Payload:' in stdout, vulnerable should be True."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="\x1b[92m[+]\x1b[0m Payload: <script>alert(1)</script>\n"
                   "[!] Efficiency: 100\n[!] Confidence: 10\n",
            stderr="",
        )
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is True
        assert result["exit_code"] == 0
        assert "Payload:" in result["stdout"]
        assert result.get("error") is None

    @patch("xssspect.external_runner.subprocess.run")
    def test_no_vulnerability(self, mock_run: MagicMock) -> None:
        """Clean stdout → vulnerable should be False."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="[~] Checking for DOM vulnerabilities\n"
                   "[-] No reflection found\n",
            stderr="",
        )
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is False
        assert result["exit_code"] == 0

    @patch("xssspect.external_runner.subprocess.run")
    def test_dom_vulnerability_detected(self, mock_run: MagicMock) -> None:
        """DOM check hit marker should trigger vulnerable=True."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="[+] Potentially vulnerable objects found\n",
            stderr="",
        )
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is True

    @patch("xssspect.external_runner.subprocess.run")
    def test_cli_flags_passed_correctly(self, mock_run: MagicMock) -> None:
        """Verify the subprocess is invoked with the right CLI flags."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
            delay=3,
            timeout=120,
        )
        args_list = mock_run.call_args[0][0]
        assert "-u" in args_list
        assert "http://example.com/?q=test" in args_list
        assert "--skip" in args_list
        assert "--skip-dom" in args_list
        assert "-d" in args_list
        assert "3" in args_list
        # timeout kwarg
        assert mock_run.call_args[1]["timeout"] == 120


# ---------------------------------------------------------------------------
# run_xsstrike — error handling
# ---------------------------------------------------------------------------

class TestRunXSStrikeErrors:
    @patch("xssspect.external_runner.subprocess.run")
    def test_timeout_expired(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="xsstrike", timeout=300)
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is False
        assert result["exit_code"] == -1
        assert "timed out" in result["error"]

    @patch("xssspect.external_runner.subprocess.run")
    def test_file_not_found(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError("No such file: xsstrike.py")
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="bad/path/xsstrike.py",
        )
        assert result["vulnerable"] is False
        assert result["exit_code"] == -1
        assert "not found" in result["error"]

    @patch("xssspect.external_runner.subprocess.run")
    def test_generic_exception(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = OSError("Permission denied")
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is False
        assert result["exit_code"] == -1
        assert "Permission denied" in result["error"]

    @patch("xssspect.external_runner.subprocess.run")
    def test_nonzero_exit_code(self, mock_run: MagicMock) -> None:
        """Non-zero exit with no success markers → vulnerable=False."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Some error",
        )
        result = run_xsstrike(
            target_url="http://example.com/?q=test",
            xsstrike_path="XSStrike/xsstrike.py",
        )
        assert result["vulnerable"] is False
        assert result["exit_code"] == 1
        assert result["stderr"] == "Some error"


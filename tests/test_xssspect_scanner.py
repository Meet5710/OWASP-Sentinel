"""Unit tests for xssspect.scanner module."""

from unittest.mock import MagicMock, call, patch
import pytest

from xssspect.scanner import scan_url


def test_scan_url_no_parameters():
    url = "https://example.com/no-params"
    result = scan_url(url)

    assert result == {
        "url": url,
        "error": "no parameters found",
        "findings": [],
    }


@patch("xssspect.scanner.time.sleep")
@patch("xssspect.scanner.check_payload_execution")
@patch("xssspect.scanner.load_payloads")
def test_scan_url_vulnerable_execution(mock_load_payloads, mock_check_exec, mock_sleep):
    mock_load_payloads.return_value = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    mock_check_exec.side_effect = [
        # First payload executes
        {"payload": "<script>alert(1)</script>", "executed": True, "dialog_message": "1", "reflected": True},
        # Second payload reflects but doesn't execute
        {"payload": "<img src=x onerror=alert(1)>", "executed": False, "dialog_message": None, "reflected": True},
    ]

    target_url = "https://example.com/search?q=test"
    result = scan_url(target_url, delay=0.1)

    assert result["url"] == target_url
    assert result["parameters_tested"] == ["q"]
    assert result["vulnerable"] is True
    assert len(result["findings"]) == 2
    assert result["findings"][0] == {
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "executed": True,
        "reflected": True,
        "dialog_message": "1",
    }
    assert result["findings"][1] == {
        "parameter": "q",
        "payload": "<img src=x onerror=alert(1)>",
        "executed": False,
        "reflected": True,
        "dialog_message": None,
    }
    assert mock_sleep.call_count == 2
    mock_sleep.assert_called_with(0.1)


@patch("xssspect.scanner.time.sleep")
@patch("xssspect.scanner.check_payload_execution")
@patch("xssspect.scanner.load_payloads")
def test_scan_url_not_vulnerable_multiple_params(mock_load_payloads, mock_check_exec, mock_sleep):
    mock_load_payloads.return_value = ["<script>alert(1)</script>"]
    mock_check_exec.return_value = {
        "payload": "<script>alert(1)</script>",
        "executed": False,
        "dialog_message": None,
        "reflected": False,
    }

    target_url = "https://example.com/filter?category=tech&page=1"
    result = scan_url(target_url, delay=0)

    assert result["url"] == target_url
    assert result["parameters_tested"] == ["category", "page"]
    assert result["vulnerable"] is False
    assert len(result["findings"]) == 2
    assert mock_sleep.call_count == 0  # delay is 0


@patch("xssspect.scanner.check_payload_execution")
@patch("xssspect.scanner.load_payloads")
def test_scan_url_custom_payload_file(mock_load_payloads, mock_check_exec):
    mock_load_payloads.return_value = ["test_payload"]
    mock_check_exec.return_value = {
        "payload": "test_payload",
        "executed": False,
        "dialog_message": None,
        "reflected": False,
    }

    scan_url("https://example.com/view?id=10", payload_file="custom_probes.txt", delay=0)
    mock_load_payloads.assert_called_once_with("custom_probes.txt")


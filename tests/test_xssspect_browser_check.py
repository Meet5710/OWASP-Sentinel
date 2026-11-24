"""Unit tests for xssspect.browser_check module."""

from unittest.mock import MagicMock, patch
import pytest

from xssspect.browser_check import check_payload_execution


def test_check_payload_execution_success_with_dialog():
    payload = "<script>alert(1)</script>"
    test_url = "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

    mock_page = MagicMock()
    mock_browser = MagicMock()
    mock_playwright = MagicMock()

    # Capture dialog handler registered via page.on("dialog", handler)
    dialog_handler = None

    def capture_on(event, handler):
        nonlocal dialog_handler
        if event == "dialog":
            dialog_handler = handler

    mock_page.on.side_effect = capture_on

    def simulate_goto(url, timeout):
        # Simulate browser firing dialog event during page load
        if dialog_handler:
            mock_dialog = MagicMock()
            mock_dialog.message = "1"
            mock_dialog.type = "alert"
            dialog_handler(mock_dialog)
            mock_dialog.dismiss.assert_called_once()

    mock_page.goto.side_effect = simulate_goto
    mock_page.content.return_value = "<html><body><script>alert(1)</script></body></html>"

    mock_browser.new_page.return_value = mock_page
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("xssspect.browser_check.sync_playwright") as mock_sync_pw:
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_playwright
        mock_ctx.__exit__.return_value = None
        mock_sync_pw.return_value = mock_ctx

        result = check_payload_execution(test_url, payload, timeout=5)

    assert result["payload"] == payload
    assert result["executed"] is True
    assert result["dialog_message"] == "1"
    assert result["reflected"] is True
    assert "error" not in result
    mock_page.goto.assert_called_once_with(test_url, timeout=5000)
    mock_browser.close.assert_called_once()


def test_check_payload_execution_no_execution_encoded_reflection():
    payload = "<script>alert(1)</script>"
    test_url = "https://example.com/search?q=safe"

    mock_page = MagicMock()
    mock_browser = MagicMock()
    mock_playwright = MagicMock()

    # HTML contains escaped text, not raw unencoded payload
    mock_page.content.return_value = "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    mock_browser.new_page.return_value = mock_page
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("xssspect.browser_check.sync_playwright") as mock_sync_pw:
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_playwright
        mock_ctx.__exit__.return_value = None
        mock_sync_pw.return_value = mock_ctx

        result = check_payload_execution(test_url, payload, timeout=10)

    assert result["payload"] == payload
    assert result["executed"] is False
    assert result["dialog_message"] is None
    assert result["reflected"] is False
    assert "error" not in result
    mock_browser.close.assert_called_once()


def test_check_payload_execution_navigation_timeout_error():
    payload = "<script>alert(1)</script>"
    test_url = "https://example.com/hang"

    mock_page = MagicMock()
    mock_browser = MagicMock()
    mock_playwright = MagicMock()

    mock_page.goto.side_effect = TimeoutError("Navigation timeout of 10000ms exceeded")
    mock_browser.new_page.return_value = mock_page
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("xssspect.browser_check.sync_playwright") as mock_sync_pw:
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_playwright
        mock_ctx.__exit__.return_value = None
        mock_sync_pw.return_value = mock_ctx

        result = check_payload_execution(test_url, payload, timeout=10)

    assert result["payload"] == payload
    assert result["executed"] is False
    assert result["dialog_message"] is None
    assert result["reflected"] is False
    assert "error" in result
    assert "Navigation timeout" in result["error"]
    mock_browser.close.assert_called_once()


def test_check_payload_execution_playwright_missing():
    with patch("xssspect.browser_check.sync_playwright", None):
        result = check_payload_execution("https://example.com", "<script>alert(1)</script>")

    assert result["executed"] is False
    assert result["dialog_message"] is None
    assert result["reflected"] is False
    assert "Playwright is not installed" in result["error"]

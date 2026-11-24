"""Unit tests for scan_http.py module."""

from unittest.mock import patch, MagicMock
import requests
import scan_http


class MockRawHeaders:
    def __init__(self, headers_list):
        self._headers_list = headers_list

    def getlist(self, name):
        if name.lower() == "set-cookie":
            return self._headers_list
        return []


class MockRawResponse:
    def __init__(self, headers_list):
        self.headers = MockRawHeaders(headers_list)

    def getlist(self, name):
        return self.headers.getlist(name)


def test_check_security_headers_missing_all() -> None:
    """When all required security headers are absent, 4 findings with A02 are returned."""
    mock_resp = MagicMock()
    mock_resp.headers = {"Server": "Apache/2.4"}

    with patch("requests.get", return_value=mock_resp):
        findings = scan_http.check_security_headers("https://example.com")

    assert len(findings) == 4
    for f in findings:
        assert f["owasp_id"] == "A02"
        assert f["source"] == "scanner"
    headers_found = [f["header"] for f in findings]
    assert "Content-Security-Policy" in headers_found
    assert "Strict-Transport-Security" in headers_found
    assert "X-Frame-Options" in headers_found
    assert "X-Content-Type-Options" in headers_found


def test_check_security_headers_all_present() -> None:
    """When all required security headers are present, 0 findings are returned."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    }

    with patch("requests.get", return_value=mock_resp):
        findings = scan_http.check_security_headers("https://secure.example.com")

    assert len(findings) == 0


def test_check_cookie_flags_missing_flags() -> None:
    """Flag cookies missing Secure or HttpOnly attributes."""
    mock_resp = MagicMock()
    cookie_entries = [
        "session_id=abc123; Path=/",  # Missing both
        "remember_me=1; Path=/; Secure",  # Missing HttpOnly
        "csrf_token=xyz; Path=/; HttpOnly; Secure",  # Fully secured
    ]
    mock_resp.raw = MockRawResponse(cookie_entries)
    mock_resp.headers = {}

    with patch("requests.get", return_value=mock_resp):
        findings = scan_http.check_cookie_flags("https://example.com")

    assert len(findings) == 2
    session_f = next(f for f in findings if f["cookie"] == "session_id")
    assert session_f["owasp_id"] == "A07"
    assert "HttpOnly" in session_f["missing_flags"]
    assert "Secure" in session_f["missing_flags"]

    remember_f = next(f for f in findings if f["cookie"] == "remember_me")
    assert remember_f["owasp_id"] == "A07"
    assert "HttpOnly" in remember_f["missing_flags"]
    assert "Secure" not in remember_f["missing_flags"]


def test_check_reflected_probe_reflected() -> None:
    """Verify probe is appended to parameter and reflection is detected."""
    mock_resp = MagicMock()
    mock_resp.text = "Search results for: query_valuerEdAm0nPr0bE"

    with patch("requests.get", return_value=mock_resp) as mock_get:
        res = scan_http.check_reflected_probe("http://example.com/search?q=query_value", "q")

    assert res["reflected"] is True
    assert res["url"] == "http://example.com/search?q=query_valuerEdAm0nPr0bE"
    mock_get.assert_called_once()


def test_check_reflected_probe_not_reflected() -> None:
    """Verify when response does not contain probe, reflected is False."""
    mock_resp = MagicMock()
    mock_resp.text = "Hello World!"

    with patch("requests.get", return_value=mock_resp):
        res = scan_http.check_reflected_probe("http://example.com/api", "param1", probe="custom_probe_99")

    assert res["reflected"] is False
    assert res["url"] == "http://example.com/api?param1=custom_probe_99"


def test_network_exceptions_handled_gracefully() -> None:
    """All functions must return clean defaults when requests fails."""
    with patch("requests.get", side_effect=requests.RequestException("Connection refused")):
        headers_res = scan_http.check_security_headers("http://down.target")
        cookies_res = scan_http.check_cookie_flags("http://down.target")
        probe_res = scan_http.check_reflected_probe("http://down.target?k=1", "k")

    assert headers_res == []
    assert cookies_res == []
    assert probe_res == {"reflected": False, "url": "http://down.target?k=1rEdAm0nPr0bE"}

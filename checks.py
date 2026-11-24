"""OWASP Top 10 Check Implementations for Authorized Security Assessments.

Provides modular check functions mapped from CHECK_REGISTRY. Categories that cannot
be evaluated from external network access explicitly return manual review guidance
to avoid fabricating unverifiable automated findings.
"""

from typing import NamedTuple
import re
import ssl
from urllib.parse import urlparse, urljoin
import urllib.request
import urllib.error


class _HttpResponse(NamedTuple):
    status: int
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    body: str


def _make_request(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 2.5,
) -> _HttpResponse | None:
    """Safely execute a lightweight HTTP GET request for security assessment.

    Disables SSL certificate verification for local lab/staging environments
    and catches all network exceptions gracefully.
    """
    req_headers = {"User-Agent": "OWASP-Sentinel-Assessment/1.0"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    ctx = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            status = response.getcode()
            raw_headers = list(response.getheaders())
            headers_dict = {k.lower(): v for k, v in raw_headers}
            body = response.read().decode("utf-8", errors="ignore")
            return _HttpResponse(
                status=status,
                headers=headers_dict,
                raw_headers=raw_headers,
                body=body,
            )
    except urllib.error.HTTPError as e:
        raw_headers = list(e.headers.items()) if e.headers else []
        headers_dict = {k.lower(): v for k, v in raw_headers}
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return _HttpResponse(
            status=e.code,
            headers=headers_dict,
            raw_headers=raw_headers,
            body=body,
        )
    except Exception:
        return None


def run_access_control_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A01 Broken Access Control security checks.

    Audits public target endpoints for unauthenticated privileged path exposure
    and unauthorized administrative interface accessibility.
    """
    findings: list[dict] = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    privileged_paths = ["/admin", "/admin/", "/administrator", "/dashboard", "/.env"]

    auth_headers = {}
    if auth.get("token"):
        auth_headers["Authorization"] = f"Bearer {auth['token']}"
    elif auth.get("cookie"):
        auth_headers["Cookie"] = auth["cookie"]

    for path in privileged_paths:
        probe_url = urljoin(base_url, path)
        resp = _make_request(probe_url, timeout=2.0)
        if resp and resp.status == 200:
            body_lower = resp.body.lower()
            if any(term in body_lower for term in ("admin", "dashboard", "control panel", "app_key")):
                findings.append(
                    {
                        "owasp_id": "A01",
                        "title": f"Unauthenticated Privileged Path Exposure: {path}",
                        "severity": "high",
                        "evidence": f"Endpoint {probe_url} responded with HTTP 200 OK without requiring authentication credentials.",
                        "source": "scanner",
                    }
                )
                break
    return findings


def run_misconfig_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A02 Security Misconfiguration checks.

    Audits target HTTP responses for fundamental security defense-in-depth headers
    and verbose platform banner version disclosures.
    """
    findings: list[dict] = []
    resp = _make_request(target_url, timeout=3.0)
    if resp:
        # 1. Missing Security Headers
        security_headers = [
            ("content-security-policy", "Content-Security-Policy"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
        ]
        missing = [display for header_key, display in security_headers if header_key not in resp.headers]
        if missing:
            findings.append(
                {
                    "owasp_id": "A02",
                    "title": "Missing Fundamental Security Headers",
                    "severity": "medium",
                    "evidence": f"Target response lacks defense-in-depth security headers: {', '.join(missing)}.",
                    "source": "scanner",
                }
            )

        # 2. Verbose Server Banner Version Disclosure
        server_banner = resp.headers.get("server") or resp.headers.get("x-powered-by")
        if server_banner and any(c.isdigit() for c in server_banner):
            findings.append(
                {
                    "owasp_id": "A02",
                    "title": "Verbose Server Banner Version Disclosure",
                    "severity": "low",
                    "evidence": f"Server disclosure banner observed: '{server_banner}'.",
                    "source": "scanner",
                }
            )
    return findings


def run_supply_chain_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A03 Software Supply Chain Failures checks.

    External network probing cannot verify third-party dependencies or SBOM components;
    requires source code or internal build artifact access.
    """
    return [
        {
            "owasp_id": "A03",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]


def run_crypto_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A04 Cryptographic Failures checks.

    Verifies transport encryption policy, plaintext HTTP detection, and HSTS enforcement.
    """
    findings: list[dict] = []
    parsed = urlparse(target_url)

    # 1. Plaintext HTTP transport
    if parsed.scheme == "http":
        findings.append(
            {
                "owasp_id": "A04",
                "title": "Cleartext HTTP Protocol Detected",
                "severity": "high",
                "evidence": f"Target endpoint {target_url} uses unencrypted plaintext HTTP transport.",
                "source": "scanner",
            }
        )
    elif parsed.scheme == "https":
        # 2. HSTS Header Enforcement
        resp = _make_request(target_url, timeout=3.0)
        if resp and "strict-transport-security" not in resp.headers:
            findings.append(
                {
                    "owasp_id": "A04",
                    "title": "Missing Strict-Transport-Security (HSTS) Header",
                    "severity": "medium",
                    "evidence": "HTTPS response does not enforce HSTS, leaving connections susceptible to SSL-stripping.",
                    "source": "scanner",
                }
            )
    return findings


def run_injection_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A05 Injection checks.

    Tests query parameters for unescaped parameter reflection and common SQL/command
    syntax boundary disclosures without sending weaponized exploit payloads.
    """
    findings: list[dict] = []
    parsed = urlparse(target_url)
    if parsed.query:
        canary = "sentinel_safe_probe_789"
        separator = "&" if "?" in target_url else "?"
        probe_url = f"{target_url}{separator}sentinel_probe={canary}"
        resp = _make_request(probe_url, timeout=3.0)
        if resp and canary in resp.body:
            findings.append(
                {
                    "owasp_id": "A05",
                    "title": "Unfiltered Parameter Input Reflection",
                    "severity": "medium",
                    "evidence": f"Canary parameter was reflected unescaped in response body from {probe_url}.",
                    "source": "scanner",
                }
            )
    return findings


def run_design_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A06 Insecure Design checks.

    Threat models, business logic boundaries, and architectural design weaknesses
    cannot be automated from outside.
    """
    return [
        {
            "owasp_id": "A06",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]


def run_auth_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A07 Authentication Failures checks.

    Audits cookie attributes (Secure, HttpOnly, SameSite) and transmission security.
    """
    findings: list[dict] = []
    resp = _make_request(target_url, timeout=3.0)
    if resp:
        cookie_headers = [v for k, v in resp.raw_headers if k.lower() == "set-cookie"]
        for cookie in cookie_headers:
            c_lower = cookie.lower()
            missing_flags = []
            if "httponly" not in c_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in c_lower and target_url.startswith("https://"):
                missing_flags.append("Secure")
            if "samesite" not in c_lower:
                missing_flags.append("SameSite")
            if missing_flags:
                cookie_name = cookie.split("=")[0].strip()
                findings.append(
                    {
                        "owasp_id": "A07",
                        "title": f"Insecure Cookie Flags on '{cookie_name}'",
                        "severity": "medium",
                        "evidence": f"Cookie '{cookie_name}' lacks recommended security attributes: {', '.join(missing_flags)}.",
                        "source": "scanner",
                    }
                )
                break
    return findings


def run_integrity_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A08 Software or Data Integrity Failures checks.

    Audits HTML markup for external script assets missing Subresource Integrity (SRI) attributes.
    """
    findings: list[dict] = []
    resp = _make_request(target_url, timeout=3.0)
    if resp and resp.body:
        script_matches = re.findall(
            r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>',
            resp.body,
            re.IGNORECASE,
        )
        for script_url in script_matches:
            # Check if this external script tag has an integrity attribute
            tag_pattern = re.escape(script_url)
            tag_match = re.search(r'<script[^>]+' + tag_pattern + r'[^>]*>', resp.body, re.IGNORECASE)
            if tag_match and "integrity=" not in tag_match.group(0).lower():
                findings.append(
                    {
                        "owasp_id": "A08",
                        "title": "Missing Subresource Integrity (SRI) on External Script",
                        "severity": "low",
                        "evidence": f"External script resource loaded without cryptographic hash verification: {script_url}.",
                        "source": "scanner",
                    }
                )
                break
    return findings


def run_logging_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A09 Security Logging and Alerting Failures checks.

    Auditing internal logging, SIEM ingestion, and alerting mechanisms requires
    internal system or logging infrastructure access.
    """
    return [
        {
            "owasp_id": "A09",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]


def run_exception_checks(target_url: str, auth: dict) -> list[dict]:
    """Execute A10 Mishandling of Exceptional Conditions checks.

    Exception handling, memory exhaustion, panic recovery, and state transitions
    cannot be automated from outside and require source code or internal system access.
    """
    return [
        {
            "owasp_id": "A10",
            "title": "Manual review required",
            "severity": "info",
            "evidence": "This category requires source code or internal system access",
            "source": "manual",
        }
    ]


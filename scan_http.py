"""Non-destructive HTTP Security Checks.

Provides passive and non-destructive HTTP response auditing using `requests`.
Audits missing security headers (A02), insecure cookie flags (A07), and benign
canary parameter reflection (A05) without sending attack payloads or running
exploit tools.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import requests
import urllib3

# Suppress insecure HTTPS connection warnings in authorized assessment environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUIRED_SECURITY_HEADERS: list[str] = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def check_security_headers(url: str, timeout: float = 5.0) -> list[dict]:
    """Send a GET request and inspect response headers for missing security headers (A02).

    Checks for:
    - Content-Security-Policy
    - Strict-Transport-Security
    - X-Frame-Options
    - X-Content-Type-Options

    Args:
        url: Target HTTP/HTTPS endpoint URL.
        timeout: Maximum seconds to wait for network response.

    Returns:
        List of finding dictionaries with owasp_id="A02".
    """
    findings: list[dict] = []
    headers = {"User-Agent": "OWASP-Sentinel-HTTP-Audit/1.0"}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return findings

    # Case-insensitive header lookup
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for required_header in REQUIRED_SECURITY_HEADERS:
        if required_header.lower() not in resp_headers_lower:
            findings.append(
                {
                    "owasp_id": "A02",
                    "header": required_header,
                    "title": f"Missing Security Header: {required_header}",
                    "severity": "medium",
                    "evidence": f"Response from {url} is missing the recommended '{required_header}' security header.",
                    "source": "scanner",
                }
            )

    return findings


def check_cookie_flags(url: str, timeout: float = 5.0) -> list[dict]:
    """Parse Set-Cookie headers and flag cookies missing Secure or HttpOnly attributes (A07).

    Args:
        url: Target HTTP/HTTPS endpoint URL.
        timeout: Maximum seconds to wait for network response.

    Returns:
        List of finding dictionaries with owasp_id="A07".
    """
    findings: list[dict] = []
    headers = {"User-Agent": "OWASP-Sentinel-HTTP-Audit/1.0"}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return findings

    # Extract raw Set-Cookie header entries
    set_cookie_headers: list[str] = []
    if hasattr(resp, "raw") and resp.raw is not None:
        raw_headers = getattr(resp.raw, "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            try:
                set_cookie_headers = raw_headers.getlist("Set-Cookie")
            except Exception:
                pass
        elif hasattr(resp.raw, "getlist"):
            try:
                set_cookie_headers = resp.raw.getlist("Set-Cookie")
            except Exception:
                pass

    if not set_cookie_headers and hasattr(resp, "headers") and resp.headers:
        cookie_val = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
        if isinstance(cookie_val, list):
            set_cookie_headers = cookie_val
        elif isinstance(cookie_val, str) and cookie_val:
            set_cookie_headers = [cookie_val]

    # Fallback to resp.cookies if Set-Cookie header strings are not extracted
    if not set_cookie_headers and hasattr(resp, "cookies") and resp.cookies:
        for c in resp.cookies:
            is_secure = getattr(c, "secure", False)
            rest_keys = {k.lower() for k in getattr(c, "_rest", {}).keys()}
            is_httponly = "httponly" in rest_keys or (
                hasattr(c, "has_nonstandard_attr") and c.has_nonstandard_attr("HttpOnly")
            )
            missing_flags = []
            if not is_httponly:
                missing_flags.append("HttpOnly")
            if not is_secure:
                missing_flags.append("Secure")
            if missing_flags:
                findings.append(
                    {
                        "owasp_id": "A07",
                        "cookie": c.name,
                        "missing_flags": missing_flags,
                        "title": f"Cookie Missing Security Flags: {c.name}",
                        "severity": "medium",
                        "evidence": f"Cookie '{c.name}' lacks: {', '.join(missing_flags)}.",
                        "source": "scanner",
                    }
                )
        return findings

    for cookie_header in set_cookie_headers:
        parts = [p.strip() for p in cookie_header.split(";") if p.strip()]
        if not parts:
            continue

        cookie_name_val = parts[0]
        cookie_name = cookie_name_val.split("=")[0].strip() if "=" in cookie_name_val else cookie_name_val

        attributes_lower = {p.lower() for p in parts[1:]}

        missing_flags: list[str] = []
        if "httponly" not in attributes_lower:
            missing_flags.append("HttpOnly")
        if "secure" not in attributes_lower:
            missing_flags.append("Secure")

        if missing_flags:
            findings.append(
                {
                    "owasp_id": "A07",
                    "cookie": cookie_name,
                    "missing_flags": missing_flags,
                    "title": f"Cookie Missing Security Flags: {cookie_name}",
                    "severity": "medium",
                    "evidence": f"Cookie '{cookie_name}' lacks: {', '.join(missing_flags)}. Raw: {cookie_header}",
                    "source": "scanner",
                }
            )

    return findings


def check_reflected_probe(url: str, param: str, probe: str = "rEdAm0nPr0bE", timeout: float = 5.0) -> dict:
    """Append a harmless probe string to a URL parameter value and test for unencoded reflection (A05).

    Only verifies unencoded reflection in the HTTP response body; does not send or execute exploit payloads.

    Args:
        url: Target HTTP/HTTPS URL containing or receiving the query parameter.
        param: Name of the parameter to probe.
        probe: Harmless unique canary string (default: 'rEdAm0nPr0bE').
        timeout: Maximum seconds to wait for network response.

    Returns:
        Dict formatted as {"reflected": bool, "url": str}.
    """
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query, keep_blank_values=True)

    if param in query_dict:
        # Append probe to existing parameter values
        query_dict[param] = [val + probe for val in query_dict[param]]
    else:
        query_dict[param] = [probe]

    new_query = urlencode(query_dict, doseq=True)
    target_probe_url = urlunparse(parsed._replace(query=new_query))

    headers = {"User-Agent": "OWASP-Sentinel-HTTP-Audit/1.0"}

    try:
        resp = requests.get(target_probe_url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        # Check if probe appears unencoded in response body
        reflected = probe in resp.text
        return {"reflected": reflected, "url": target_probe_url}
    except requests.RequestException:
        return {"reflected": False, "url": target_probe_url}


def check_access_control(url: str, auth: dict | None = None, timeout: float = 5.0) -> list[dict]:
    """Inspect common privileged endpoints for unauthenticated access (A01).

    Non-destructively probes common administrative paths without sending exploit payloads.

    Args:
        url: Target HTTP/HTTPS endpoint URL.
        auth: Optional authentication credentials dictionary.
        timeout: Maximum seconds to wait for network response.

    Returns:
        List of finding dictionaries with owasp_id="A01".
    """
    findings: list[dict] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    privileged_paths = ["/admin", "/admin/", "/administrator", "/dashboard", "/.env"]

    headers = {"User-Agent": "OWASP-Sentinel-HTTP-Audit/1.0"}
    if auth:
        if auth.get("token"):
            headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth.get("cookie"):
            headers["Cookie"] = auth["cookie"]

    for path in privileged_paths:
        probe_url = urljoin(base_url, path)
        try:
            resp = requests.get(probe_url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if any(term in body_lower for term in ("admin", "dashboard", "control panel", "app_key")):
                    findings.append(
                        {
                            "owasp_id": "A01",
                            "title": f"Unauthenticated Privileged Path Exposure: {path}",
                            "severity": "high",
                            "evidence": f"Endpoint {probe_url} returned HTTP 200 without requiring authentication.",
                            "source": "scanner",
                        }
                    )
                    break
        except requests.RequestException:
            continue

    return findings


def check_reflected_parameters(
    url: str,
    params: list[str] | None = None,
    probe: str = "rEdAm0nPr0bE",
    timeout: float = 5.0,
) -> list[dict]:
    """Audit query parameters for unencoded reflection findings (A05).

    Args:
        url: Target HTTP/HTTPS URL with or without query parameters.
        params: Optional list of parameter names to test. Defaults to query params in url or ['q'].
        probe: Canary probe string.
        timeout: Network timeout in seconds.

    Returns:
        List of finding dictionaries with owasp_id="A05".
    """
    findings: list[dict] = []
    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query, keep_blank_values=True)

    test_params = params or list(query_dict.keys()) or ["q"]

    for param in test_params:
        result = check_reflected_probe(url, param=param, probe=probe, timeout=timeout)
        if result.get("reflected"):
            findings.append(
                {
                    "owasp_id": "A05",
                    "param": param,
                    "title": f"Reflected Input Detected: Parameter '{param}'",
                    "severity": "medium",
                    "evidence": f"Canary probe string was reflected unencoded in response from {result['url']}.",
                    "source": "scanner",
                }
            )

    return findings

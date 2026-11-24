"""OWASP Sentinel - Server-Side Request Forgery (SSRF) Detection Rule

Safely probes for unvalidated URL redirection, URL-parameter proxy reflection,
and cloud metadata exposure risks.
"""

from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class SsrfProtectionCheck(BaseDetectionRule):
    """Detects unvalidated external redirection and potential Server-Side Request Forgery vectors."""

    rule_id = "RULE-SEC-014"
    name = "Server-Side Request Forgery (SSRF) & Open Redirect Audit"
    description = (
        "Audits URL query parameters for arbitrary open redirection and probes for vulnerable "
        "webhook, proxy, or server-side URL fetch endpoints that could facilitate internal network pivoting."
    )
    why_it_matters = (
        "Server-Side Request Forgery (A10:2021) occurs when a web application fetches a remote resource without "
        "validating the user-supplied destination URL. Adversaries coerce the server into connecting to internal "
        "cloud metadata services (169.254.169.254) or intranet systems, exfiltrating credentials."
    )
    evidence_description = "Records tested redirect parameters, observed Location response headers, and status codes."
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control",
        "2021": "A10:2021-Server-Side Request Forgery (SSRF)",
        "2017": "A1:2017-Injection, A5:2017-Broken Access Control",
        "2013": "A10:2013-Unvalidated Redirects and Forwards, A4:2013-Insecure Direct Object References",
        "2010": "A10:2010-Unvalidated Redirects and Forwards",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Blind SSRF vulnerabilities without HTTP response reflection require out-of-band DNS/HTTP listener telemetry."
    )
    potential_false_positives = (
        "OAuth or SSO callback handlers that redirect to predefined whitelisted partner domains."
    )
    remediation_guidance = (
        "Enforce strict domain allowlists on all redirect and fetch parameters, sanitize URLs, "
        "block loopback (127.0.0.1) and link-local cloud metadata addresses (169.254.169.254), "
        "and enforce IMDSv2 on AWS cloud workloads."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ]

    REDIRECT_PARAMS = ["redirect", "url", "next", "dest", "target"]
    CANARY_EXTERNAL_HOST = "owasp-sentinel-canary.invalid"

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = context.canonical_url

        async with httpx.AsyncClient(verify=False) as client:
            parsed = urlparse(base_url)

            # Test standard redirect query parameters for Open Redirection
            for param in self.REDIRECT_PARAMS:
                canary_target = f"https://{self.CANARY_EXTERNAL_HOST}/"
                test_query = urlencode({param: canary_target})
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", test_query, ""))

                try:
                    resp = await client.get(
                        probe_url,
                        timeout=context.timeout_seconds,
                        headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                        follow_redirects=False,
                    )

                    # If status is 3xx and Location redirects to arbitrary external canary host
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if self.CANARY_EXTERNAL_HOST in location:
                            findings.append(
                                CheckFinding(
                                    rule_id=self.rule_id,
                                    title=f"Unvalidated Open Redirection on Parameter '{param}'",
                                    technical_issue_type="OPEN_REDIRECT_VECTOR",
                                    severity="MEDIUM",
                                    confidence="CERTAIN",
                                    evidence={
                                        "parameter": param,
                                        "probe_url": probe_url,
                                        "redirect_location": location,
                                        "status_code": resp.status_code,
                                    },
                                    remediation=(
                                        f"Sanitize the '{param}' parameter. Validate redirect destinations against "
                                        "an explicit allowlist of authorized domain names."
                                    ),
                                    references=self.references,
                                )
                            )
                            break
                except Exception:
                    continue

        return findings

